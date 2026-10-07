package oppa

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ net.PacketConn = (*UDPConn)(nil)
	_ N.PacketConn   = (*UDPConn)(nil)
)

// UDPConn is a UDP-over-TLS data channel. Writes are serialized so two frames
// can never interleave, reads are serialized because the channel has a single
// reader.
type UDPConn struct {
	conn        net.Conn
	channel     M.Socksaddr
	writeAccess sync.Mutex
	readAccess  sync.Mutex
	closeOnce   sync.Once
}

func NewUDPConn(conn net.Conn, channel M.Socksaddr) *UDPConn {
	return &UDPConn{conn: conn, channel: channel}
}

// Channel reports the channel address carried in outgoing frames.
func (c *UDPConn) Channel() M.Socksaddr {
	return c.channel
}

// WritePacketBytes encodes and writes one UDP data frame.
func (c *UDPConn) WritePacketBytes(payload []byte, destination M.Socksaddr) error {
	frame, err := EncodeUDPFrame(c.channel, destination, payload)
	if err != nil {
		return err
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return writeFull(c.conn, frame)
}

func (c *UDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.WritePacketBytes(buffer.Bytes(), destination)
}

func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsValid() {
		return 0, E.Cause(ErrInvalidAddress, "destination from ", addr)
	}
	err := c.WritePacketBytes(p, destination)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UDPConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	_, destination, payloadLength, err := c.readFrameHeader()
	if err != nil {
		return M.Socksaddr{}, err
	}
	addressable := buffer.FreeLen()
	if payloadLength > addressable {
		if addressable > 0 {
			if _, err = io.ReadFull(c.conn, buffer.Extend(addressable)); err != nil {
				return M.Socksaddr{}, E.Cause(err, "read payload")
			}
		}
		if _, err = io.CopyN(io.Discard, c.conn, int64(payloadLength-addressable)); err != nil {
			return M.Socksaddr{}, E.Cause(err, "discard oversized payload")
		}
		return destination, nil
	}
	if payloadLength > 0 {
		if _, err = io.ReadFull(c.conn, buffer.Extend(payloadLength)); err != nil {
			return M.Socksaddr{}, E.Cause(err, "read payload")
		}
	}
	return destination, nil
}

func (c *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	_, destination, payloadLength, err := c.readFrameHeader()
	if err != nil {
		return 0, nil, err
	}
	if payloadLength == 0 {
		return 0, destination.UDPAddr(), nil
	}
	copied := payloadLength
	if copied > len(p) {
		copied = len(p)
	}
	n, err := io.ReadFull(c.conn, p[:copied])
	if err != nil {
		return n, nil, E.Cause(err, "read payload")
	}
	if copied < payloadLength {
		if _, err = io.CopyN(io.Discard, c.conn, int64(payloadLength-copied)); err != nil {
			return n, nil, E.Cause(err, "discard oversized payload")
		}
	}
	return n, destination.UDPAddr(), nil
}

// readFrameHeader reads the length prefix and both addresses. The caller must
// hold readAccess so the frame body stays contiguous on the stream.
func (c *UDPConn) readFrameHeader() (channel M.Socksaddr, destination M.Socksaddr, payloadLength int, err error) {
	var rawLength [2]byte
	if _, err = io.ReadFull(c.conn, rawLength[:]); err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, 0, E.Cause(err, "read frame length")
	}
	bodyLength := int(binary.BigEndian.Uint16(rawLength[:]))
	if bodyLength == 0 {
		return M.Socksaddr{}, M.Socksaddr{}, 0, E.Cause(ErrInvalidAddress, "empty frame body")
	}
	if bodyLength > MaxUDPBody {
		return M.Socksaddr{}, M.Socksaddr{}, 0, E.Cause(ErrFrameTooLarge, "got ", bodyLength)
	}
	channel, err = ReadAddress(c.conn)
	if err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, 0, E.Cause(err, "decode channel address")
	}
	destination, err = ReadAddress(c.conn)
	if err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, 0, E.Cause(err, "decode destination address")
	}
	channelLength, err := AddressLength(channel)
	if err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, 0, err
	}
	destinationLength, err := AddressLength(destination)
	if err != nil {
		return M.Socksaddr{}, M.Socksaddr{}, 0, err
	}
	payloadLength = bodyLength - channelLength - destinationLength
	if payloadLength < 0 {
		return M.Socksaddr{}, M.Socksaddr{}, 0, E.Cause(ErrInvalidAddress, "invalid frame body length ", bodyLength)
	}
	return channel, destination, payloadLength, nil
}

func (c *UDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
	})
	return err
}

func (c *UDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
