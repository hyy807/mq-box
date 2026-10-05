package aha

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// The AHAspeed data plane forwards only traffic for the address the server
// accepted in Cx-Tunnel-IP, and an address already held by another session is
// answered with a plain HTTP 404 instead of a tunnel. A connection is therefore
// only usable after a probe proves the peer returns traffic for our address.
const (
	probeDestination    = "1.1.1.1"
	probePort           = 80
	probeTimeout        = 5 * time.Second
	probeSourcePortLow  = 40000
	probeSourcePortSpan = 20000
)

// The tunnel address is a per-session resource inside the provider's 10.10.10.0/24:
// the server answers an address already held by another session with a plain HTTP
// 404, so a fixed value (the documented 10.10.10.2) can never establish a tunnel.
const (
	TunnelGateway = "10.10.10.250"
	tunnelLow     = 3
	tunnelSpan    = 250
)

// RandomTunnelAddress returns a session address to offer the server. Callers that
// see the address refused must offer a different one.
func RandomTunnelAddress() string {
	return fmt.Sprintf("10.10.10.%d", tunnelLow+randomUint32()%tunnelSpan)
}

func randomUint32() uint32 {
	var value [4]byte
	if _, err := rand.Read(value[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(value[:])
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func addChecksum(sum uint32, p []byte) uint32 {
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p[:2]))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	return sum
}

// BuildProbe builds one IPv4/TCP SYN carrying the tunnel address the server
// accepted. The probe destination is a fixed, always-reachable address so the
// only variable is the tunnel itself.
func BuildProbe(tunnelAddress string) (packet []byte, sourcePort uint16, sequence uint32, err error) {
	source, err := netip.ParseAddr(tunnelAddress)
	if err != nil || !source.Is4() {
		return nil, 0, 0, fmt.Errorf("aha: invalid tunnel address %q", tunnelAddress)
	}
	destination, err := netip.ParseAddr(probeDestination)
	if err != nil {
		return nil, 0, 0, err
	}
	sourcePort = uint16(probeSourcePortLow + randomUint32()%probeSourcePortSpan)
	sequence = randomUint32()
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], probePort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	segment[12] = 5 << 4
	segment[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(segment[14:16], 64240)
	pseudo := make([]byte, 0, 12+len(segment))
	pseudo = append(pseudo, source.AsSlice()...)
	pseudo = append(pseudo, destination.AsSlice()...)
	pseudo = append(pseudo, 0, 6)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(segment)))
	pseudo = append(pseudo, segment...)
	binary.BigEndian.PutUint16(segment[16:18], foldChecksum(addChecksum(0, pseudo)))
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+len(segment)))
	binary.BigEndian.PutUint16(header[4:6], uint16(randomUint32()))
	binary.BigEndian.PutUint16(header[6:8], 0x4000)
	header[8] = 64
	header[9] = 6
	copy(header[12:16], source.AsSlice())
	copy(header[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(header[10:12], foldChecksum(addChecksum(0, header)))
	return append(header, segment...), sourcePort, sequence, nil
}

// validateProbeResponse accepts only the SYN/ACK that answers our exact probe:
// the same tunnels are also used for unrelated traffic, so matching the five
// tuple and the sequence number is what proves our address carries returns.
func validateProbeResponse(packet []byte, tunnelAddress string, sourcePort uint16, sequence uint32) error {
	if len(packet) < 40 || packet[0]>>4 != 4 {
		return fmt.Errorf("aha: probe response is not IPv4")
	}
	headerLength := int(packet[0]&15) * 4
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || length != len(packet) || length < headerLength+20 {
		return fmt.Errorf("aha: probe response has an invalid IPv4 length")
	}
	if packet[9] != 6 {
		return fmt.Errorf("aha: probe response is not TCP")
	}
	destination, err := netip.ParseAddr(tunnelAddress)
	if err != nil {
		return err
	}
	if !bytes.Equal(packet[16:20], destination.AsSlice()) {
		return fmt.Errorf("aha: probe response is not addressed to the tunnel address")
	}
	source, _ := netip.ParseAddr(probeDestination)
	if !bytes.Equal(packet[12:16], source.AsSlice()) {
		return fmt.Errorf("aha: probe response is not from the probe destination")
	}
	segment := packet[headerLength:]
	if binary.BigEndian.Uint16(segment[0:2]) != probePort {
		return fmt.Errorf("aha: probe response has an unexpected source port")
	}
	if binary.BigEndian.Uint16(segment[2:4]) != sourcePort {
		return fmt.Errorf("aha: probe response does not answer our probe port")
	}
	if segment[13]&0x12 != 0x12 {
		return fmt.Errorf("aha: probe response is not SYN/ACK")
	}
	if binary.BigEndian.Uint32(segment[8:12]) != sequence+1 {
		return fmt.Errorf("aha: probe response acknowledges the wrong sequence")
	}
	return nil
}

// ProbeTunnel proves the handshake produced a working data plane. The peer
// answers an address it did not accept with an HTTP status line instead of a
// tunnel, which is reported verbatim so the cause is never a bare timeout.
func ProbeTunnel(ctx context.Context, conn net.Conn, tunnelAddress string) error {
	packet, sourcePort, sequence, err := BuildProbe(tunnelAddress)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(probeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	// A losing race must release its connection immediately, not after the deadline.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err = WriteAll(conn, packet); err != nil {
		return fmt.Errorf("aha: sending the tunnel probe failed: %w", err)
	}
	header := make([]byte, 20)
	for {
		if _, err = io.ReadFull(conn, header); err != nil {
			return fmt.Errorf("aha: the tunnel probe got no response: %w", err)
		}
		if bytes.HasPrefix(header, []byte("HTTP/")) {
			return fmt.Errorf("aha: the tunnel was rejected with %q", strings.TrimSpace(string(header)))
		}
		if header[0]>>4 != 4 {
			return fmt.Errorf("aha: the tunnel returned a non-IPv4 stream")
		}
		headerLength := int(header[0]&15) * 4
		length := int(binary.BigEndian.Uint16(header[2:4]))
		if headerLength < 20 || length < headerLength+20 || length > 0xffff {
			return fmt.Errorf("aha: the tunnel returned an invalid IPv4 length")
		}
		packet = make([]byte, length)
		copy(packet, header)
		if _, err = io.ReadFull(conn, packet[20:]); err != nil {
			return fmt.Errorf("aha: the tunnel probe response was truncated: %w", err)
		}
		if err = validateProbeResponse(packet, tunnelAddress, sourcePort, sequence); err != nil {
			continue
		}
		return nil
	}
}
