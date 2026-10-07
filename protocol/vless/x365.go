package vless

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func x365UUID(value string) ([16]byte, error) {
	id, err := uuid.FromString(value)
	if err != nil {
		return [16]byte{}, E.Cause(err, "invalid x365 UUID")
	}
	return id, nil
}

func x365Header(key [16]byte, command byte, destination M.Socksaddr) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("X365")
	buffer.WriteByte(1)
	buffer.WriteByte(command)
	buffer.Write(key[:])
	if command != vmess.CommandMux {
		if err := vmess.AddressSerializer.WriteAddrPort(&buffer, destination); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

type x365Conn struct {
	N.ExtendedConn
	key            [16]byte
	command        byte
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func newX365Conn(conn net.Conn, key [16]byte, command byte, destination M.Socksaddr) *x365Conn {
	return &x365Conn{ExtendedConn: bufio.NewExtendedConn(conn), key: key, command: command, destination: destination}
}

func (c *x365Conn) writeRequest(payload []byte) error {
	header, err := x365Header(c.key, c.command, c.destination)
	if err != nil {
		return err
	}
	request := append(header, payload...)
	n, err := c.ExtendedConn.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err == nil {
		c.requestWritten = true
	}
	return err
}

func (c *x365Conn) readResponse() error {
	var response [5]byte
	if _, err := io.ReadFull(c.ExtendedConn, response[:]); err != nil {
		return err
	}
	if string(response[:4]) != "X365" {
		return E.New("invalid x365 response header: prefix_hex=", hex.EncodeToString(response[:]))
	}
	// 参考实现：第 5 字节是服务端状态，0 才算握手成功。
	if response[4] != 0 {
		return E.New("x365 rejected by server, status=", response[4])
	}
	c.responseRead = true
	return nil
}

func (c *x365Conn) Read(p []byte) (int, error) {
	if !c.responseRead {
		if err := c.readResponse(); err != nil {
			return 0, err
		}
	}
	return c.ExtendedConn.Read(p)
}

func (c *x365Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !c.responseRead {
		if err := c.readResponse(); err != nil {
			return err
		}
	}
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *x365Conn) Write(p []byte) (int, error) {
	if !c.requestWritten {
		if err := c.writeRequest(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.ExtendedConn.Write(p)
}

func (c *x365Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.requestWritten {
		header, err := x365Header(c.key, c.command, c.destination)
		if err != nil {
			return err
		}
		if buffer.Start() >= len(header) {
			copy(buffer.ExtendHeader(len(header)), header)
			err = c.ExtendedConn.WriteBuffer(buffer)
			if err == nil {
				c.requestWritten = true
			}
			return err
		}
		err = c.writeRequest(buffer.Bytes())
		buffer.Release()
		return err
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *x365Conn) ReaderReplaceable() bool          { return c.responseRead }
func (c *x365Conn) WriterReplaceable() bool          { return c.requestWritten }
func (c *x365Conn) NeedHandshakeForRead() bool       { return !c.responseRead }
func (c *x365Conn) NeedHandshakeForWrite() bool      { return !c.requestWritten }
func (c *x365Conn) NeedAdditionalReadDeadline() bool { return true }
func (c *x365Conn) Upstream() any                    { return c.ExtendedConn }
func (c *x365Conn) FrontHeadroom() int {
	if c.requestWritten {
		return 0
	}
	if c.command == vmess.CommandMux {
		return 22
	}
	return 22 + vmess.AddressSerializer.AddrPortLen(c.destination)
}

type x365PacketConn struct {
	*x365Conn
	destination M.Socksaddr
}

func (c *x365PacketConn) Read(p []byte) (int, error) {
	var size [2]byte
	if _, err := io.ReadFull(c.x365Conn, size[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if len(p) < length {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.x365Conn, p[:length])
}

func (c *x365PacketConn) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, E.New("x365 packet too large")
	}
	packet := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(packet, uint16(len(p)))
	copy(packet[2:], p)
	_, err := c.x365Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *x365PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if c.destination.IsFqdn() {
		return n, c.destination, err
	}
	return n, c.destination.UDPAddr(), err
}
func (c *x365PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func (h *vlessDialer) x365PacketConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	if h.xudp {
		return vmess.NewXUDPConn(newX365Conn(conn, h.x365Key, vmess.CommandMux, destination), destination), nil
	}
	if h.packetAddr {
		return nil, E.New("x365 packetaddr is not supported")
	}
	return &x365PacketConn{newX365Conn(conn, h.x365Key, vmess.CommandUDP, destination), destination}, nil
}
