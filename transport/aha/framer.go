package aha

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Framer reads exactly one IPv4 packet; io.ReadFull handles coalesced and split
// TLS records without guessing packet boundaries. A truncated tail is an error.
type Framer struct {
	Reader      io.Reader
	Writer      io.Writer
	writeAccess sync.Mutex
}

func ValidatePacket(packet []byte) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return fmt.Errorf("aha: expected IPv4 packet (HTTP fallback is not a tunnel)")
	}
	ihl := int(packet[0]&15) * 4
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || ihl > len(packet) || length != len(packet) {
		return fmt.Errorf("aha: invalid IPv4 length")
	}
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	if sum != 65535 {
		return fmt.Errorf("aha: invalid IPv4 checksum")
	}
	return nil
}

func (f *Framer) ReadPacket() ([]byte, error) {
	packet := make([]byte, 20)
	if _, err := io.ReadFull(f.Reader, packet); err != nil {
		return nil, err
	}
	if packet[0]>>4 != 4 {
		return nil, fmt.Errorf("aha: expected IPv4 packet (HTTP fallback is not a tunnel)")
	}
	ihl := int(packet[0]&15) * 4
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || length < ihl {
		return nil, fmt.Errorf("aha: invalid IPv4 length")
	}
	packet = append(packet, make([]byte, length-20)...)
	if _, err := io.ReadFull(f.Reader, packet[20:]); err != nil {
		return nil, err
	}
	if err := ValidatePacket(packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func WriteAll(writer io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := writer.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (f *Framer) WritePacket(packet []byte) error {
	if err := ValidatePacket(packet); err != nil {
		return err
	}
	f.writeAccess.Lock()
	defer f.writeAccess.Unlock()
	return WriteAll(f.Writer, packet)
}
