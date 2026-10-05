package aha

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func buildProbeResponse(t *testing.T, tunnelAddress string, sourcePort uint16, sequence uint32, flags byte) []byte {
	t.Helper()
	source, err := netip.ParseAddr(probeDestination)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := netip.ParseAddr(tunnelAddress)
	if err != nil {
		t.Fatal(err)
	}
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:2], probePort)
	binary.BigEndian.PutUint16(segment[2:4], sourcePort)
	binary.BigEndian.PutUint32(segment[4:8], 4000)
	binary.BigEndian.PutUint32(segment[8:12], sequence+1)
	segment[12] = 5 << 4
	segment[13] = flags
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], 40)
	header[8] = 64
	header[9] = 6
	copy(header[12:16], source.AsSlice())
	copy(header[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(header[10:12], 0)
	packet := append(header, segment...)
	binary.BigEndian.PutUint16(packet[10:12], ^foldChecksum(addChecksum(0, packet[:20])))
	return packet
}

func TestBuildProbeCarriesTheAcceptedAddress(t *testing.T) {
	packet, sourcePort, sequence, err := BuildProbe("10.10.10.55")
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidatePacket(packet); err != nil {
		t.Fatalf("probe packet is not a valid IPv4 packet: %v", err)
	}
	if packet[9] != 6 {
		t.Fatal("probe is not TCP")
	}
	if got := netip.AddrFrom4([4]byte(packet[12:16])); got.String() != "10.10.10.55" {
		t.Fatalf("source address = %s", got)
	}
	if got := netip.AddrFrom4([4]byte(packet[16:20])); got.String() != probeDestination {
		t.Fatalf("destination address = %s", got)
	}
	segment := packet[20:]
	if binary.BigEndian.Uint16(segment[0:2]) != sourcePort {
		t.Fatal("source port does not match the returned value")
	}
	if binary.BigEndian.Uint16(segment[2:4]) != probePort {
		t.Fatal("destination port is not the probe port")
	}
	if binary.BigEndian.Uint32(segment[4:8]) != sequence {
		t.Fatal("sequence does not match the returned value")
	}
	if segment[13] != 0x02 {
		t.Fatalf("flags = %#x", segment[13])
	}
}

func TestValidateProbeResponseRequiresTheExactAnswer(t *testing.T) {
	const address = "10.10.10.77"
	packet, sourcePort, sequence, err := BuildProbe(address)
	if err != nil {
		t.Fatal(err)
	}
	_ = packet
	answer := buildProbeResponse(t, address, sourcePort, sequence, 0x12)
	if err = validateProbeResponse(answer, address, sourcePort, sequence); err != nil {
		t.Fatalf("valid SYN/ACK rejected: %v", err)
	}
	if err = validateProbeResponse(answer, "10.10.10.78", sourcePort, sequence); err == nil {
		t.Fatal("answer addressed to another tunnel address was accepted")
	}
	if err = validateProbeResponse(answer, address, sourcePort+1, sequence); err == nil {
		t.Fatal("answer for another probe port was accepted")
	}
	if err = validateProbeResponse(buildProbeResponse(t, address, sourcePort, sequence+9, 0x12), address, sourcePort, sequence); err == nil {
		t.Fatal("answer with a wrong acknowledgement was accepted")
	}
	if err = validateProbeResponse(buildProbeResponse(t, address, sourcePort, sequence, 0x18), address, sourcePort, sequence); err == nil {
		t.Fatal("answer that is not SYN/ACK was accepted")
	}
	if err = validateProbeResponse(append([]byte("HTTP/1.1 404 Not Found\r\n"), answer...), address, sourcePort, sequence); err == nil {
		t.Fatal("HTTP fallback was accepted as a tunnel packet")
	}
}

func TestRandomTunnelAddressStaysFree(t *testing.T) {
	for i := 0; i < 1000; i++ {
		address := RandomTunnelAddress()
		parsed, err := netip.ParseAddr(address)
		if err != nil || !parsed.Is4() {
			t.Fatalf("invalid address %q", address)
		}
		if !strings.HasPrefix(address, "10.10.10.") {
			t.Fatalf("address %q left the tunnel subnet", address)
		}
		if address == "10.10.10.2" {
			t.Fatal("the address rejected by the server must never be offered")
		}
		last := parsed.As4()[3]
		if last < tunnelLow || last >= tunnelLow+tunnelSpan {
			t.Fatalf("address %q outside the offered range", address)
		}
	}
}
