package shadowquic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	CommandConnect           byte = 1
	CommandAssociateDatagram byte = 3
	CommandAssociateStream   byte = 4
	maxUDPPacketSize              = 65535
)

type wireAddress []byte

type domainAddress struct {
	host string
	port uint16
}

func (a domainAddress) Network() string { return "udp" }
func (a domainAddress) String() string  { return net.JoinHostPort(a.host, fmt.Sprint(a.port)) }

func encodeAddress(addr M.Socksaddr) (wireAddress, error) {
	if !addr.IsValid() {
		return nil, errors.New("shadowquic: invalid destination")
	}
	if addr.IsDomain() {
		name := []byte(addr.Fqdn)
		if len(name) > 255 {
			return nil, errors.New("shadowquic: domain too long")
		}
		b := make([]byte, 2+len(name)+2)
		b[0] = 3
		b[1] = byte(len(name))
		copy(b[2:], name)
		binary.BigEndian.PutUint16(b[len(b)-2:], addr.Port)
		return b, nil
	}
	ip := addr.Addr.Unmap()
	if ip.Is4() {
		b := make([]byte, 7)
		b[0] = 1
		copy(b[1:], ip.AsSlice())
		binary.BigEndian.PutUint16(b[5:], addr.Port)
		return b, nil
	}
	b := make([]byte, 19)
	b[0] = 4
	copy(b[1:], ip.AsSlice())
	binary.BigEndian.PutUint16(b[17:], addr.Port)
	return b, nil
}
func encodeNetAddress(addr net.Addr) (wireAddress, error) {
	if addr == nil {
		return nil, errors.New("shadowquic: nil address")
	}
	return encodeAddress(M.ParseSocksaddr(addr.String()))
}
func (a wireAddress) netAddr() net.Addr {
	switch a[0] {
	case 1:
		return &net.UDPAddr{IP: net.IP(a[1:5]), Port: int(binary.BigEndian.Uint16(a[5:]))}
	case 4:
		return &net.UDPAddr{IP: net.IP(a[1:17]), Port: int(binary.BigEndian.Uint16(a[17:]))}
	default:
		return domainAddress{host: string(a[2 : len(a)-2]), port: binary.BigEndian.Uint16(a[len(a)-2:])}
	}
}
func readAddress(r io.Reader) (wireAddress, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return nil, err
	}
	var remain int
	switch typ[0] {
	case 1:
		remain = 6
	case 4:
		remain = 18
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return nil, err
		}
		remain = int(size[0]) + 2
		b := make([]byte, 2+remain)
		b[0] = 3
		b[1] = size[0]
		_, err := io.ReadFull(r, b[2:])
		return b, err
	default:
		return nil, errors.New("shadowquic: invalid address type")
	}
	b := make([]byte, 1+remain)
	b[0] = typ[0]
	_, err := io.ReadFull(r, b[1:])
	return b, err
}
func unspecifiedAddress() wireAddress {
	b, _ := encodeAddress(M.SocksaddrFrom(netip.IPv4Unspecified(), 0))
	return b
}
func WriteRequest(w io.Writer, cmd byte, addr wireAddress) error {
	if _, err := w.Write(append([]byte{cmd}, addr...)); err != nil {
		return err
	}
	return nil
}
func ReadUDPControl(r io.Reader) (wireAddress, uint16, error) {
	a, err := readAddress(r)
	if err != nil {
		return nil, 0, err
	}
	id, err := ReadUint16(r)
	return a, id, err
}
func WriteUDPControl(w io.Writer, a wireAddress, id uint16) error {
	b := make([]byte, len(a)+2)
	copy(b, a)
	binary.BigEndian.PutUint16(b[len(a):], id)
	_, err := w.Write(b)
	return err
}
func EncodeDatagram(id uint16, p []byte) ([]byte, error) {
	if len(p) > maxUDPPacketSize {
		return nil, errors.New("shadowquic: packet too large")
	}
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, id)
	copy(b[2:], p)
	return b, nil
}
func DecodeDatagram(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, errors.New("shadowquic: invalid datagram")
	}
	return binary.BigEndian.Uint16(b), b[2:], nil
}
func WritePacketStreamHeader(w io.Writer, id uint16) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], id)
	_, err := w.Write(b[:])
	return err
}
func WritePacketStreamPayload(w io.Writer, p []byte) error {
	if len(p) > maxUDPPacketSize {
		return errors.New("shadowquic: packet too large")
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(p)))
	if _, err := w.Write(b[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}
func ReadUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	_, err := io.ReadFull(r, b[:])
	return binary.BigEndian.Uint16(b[:]), err
}
