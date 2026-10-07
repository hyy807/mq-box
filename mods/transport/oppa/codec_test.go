package oppa

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// Test password and vectors from the protocol specification, section 8.
const (
	testPassword = "0123456789abcdef0123456789abcdef"
	testAuth     = "3031323334353637383961626364656630313233343536373839616263646566" // ASCII testPassword
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", value, err)
	}
	return decoded
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword(testPassword); err != nil {
		t.Fatalf("32 byte password rejected: %v", err)
	}
	// 32 characters but 45 bytes in UTF-8.
	multiByte := strings.Repeat("密", 11)
	if len(multiByte) != 33 {
		t.Fatalf("unexpected test string length %d", len(multiByte))
	}
	if err := ValidatePassword(multiByte); err == nil {
		t.Fatal("multi-byte password with 11 runes accepted, want byte length check")
	}
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword(testPassword + "x"); err == nil {
		t.Fatal("33 byte password accepted")
	}
}

func TestWriteRequestVectors(t *testing.T) {
	testCases := []struct {
		name        string
		destination M.Socksaddr
		expected    string
	}{
		{
			name:        "ipv4",
			destination: M.SocksaddrFrom(netip.MustParseAddr("127.0.0.2"), 18081),
			expected:    testAuth + "01" + "017f00000246a1",
		},
		{
			name:        "domain",
			destination: M.Socksaddr{Fqdn: "capture.invalid", Port: 18082},
			expected:    testAuth + "01" + "030f" + "636170747572652e696e76616c6964" + "46a2",
		},
		{
			name:        "ipv6",
			destination: M.SocksaddrFrom(netip.MustParseAddr("::1"), 18083),
			expected:    testAuth + "01" + "04" + strings.Repeat("00", 15) + "01" + "46a3",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := WriteRequest(&buffer, testPassword, CommandTCP, testCase.destination); err != nil {
				t.Fatalf("WriteRequest: %v", err)
			}
			expected := mustHex(t, testCase.expected)
			if !bytes.Equal(buffer.Bytes(), expected) {
				t.Fatalf("wire mismatch\n got %s\nwant %s", hex.EncodeToString(buffer.Bytes()), testCase.expected)
			}
		})
	}
}

func TestWriteChannelRequest(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteChannelRequest(&buffer, testPassword); err != nil {
		t.Fatalf("WriteChannelRequest: %v", err)
	}
	expected := mustHex(t, testAuth+"02")
	if !bytes.Equal(buffer.Bytes(), expected) {
		t.Fatalf("wire mismatch\n got %s\nwant %s", hex.EncodeToString(buffer.Bytes()), hex.EncodeToString(expected))
	}
}

func TestEncodeUDPFrameVector(t *testing.T) {
	channel := M.SocksaddrFrom(netip.MustParseAddr("0.0.0.0"), 0)
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.2"), 18084)
	frame, err := EncodeUDPFrame(channel, destination, []byte("DYNAMIC_UDP_0"))
	if err != nil {
		t.Fatalf("EncodeUDPFrame: %v", err)
	}
	expected := mustHex(t, "001b01000000000000017f00000246a444594e414d49435f5544505f30")
	if !bytes.Equal(frame, expected) {
		t.Fatalf("frame mismatch\n got %s\nwant %s", hex.EncodeToString(frame), hex.EncodeToString(expected))
	}
	if len(frame) != 29 {
		t.Fatalf("frame length %d, want 29", len(frame))
	}
}

func TestDecodeUDPFrameVector(t *testing.T) {
	frame := mustHex(t, "001b01000000000000017f00000246a444594e414d49435f5544505f30")
	channel, destination, payload, err := DecodeUDPFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodeUDPFrame: %v", err)
	}
	if channel.Addr != netip.MustParseAddr("0.0.0.0") || channel.Port != 0 {
		t.Fatalf("channel %s, want 0.0.0.0:0", channel)
	}
	if destination.Addr != netip.MustParseAddr("127.0.0.2") || destination.Port != 18084 {
		t.Fatalf("destination %s, want 127.0.0.2:18084", destination)
	}
	if string(payload) != "DYNAMIC_UDP_0" {
		t.Fatalf("payload %q", payload)
	}
}

func TestAddressRoundTrip(t *testing.T) {
	longLabel := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 50)
	// 179 bytes total, every label inside the 63 byte limit.
	domains := []string{"a.b", "capture.invalid", longLabel}
	for _, domain := range domains {
		destination := M.Socksaddr{Fqdn: domain, Port: 443}
		var buffer bytes.Buffer
		if err := WriteAddress(&buffer, destination); err != nil {
			t.Fatalf("WriteAddress(%s): %v", domain, err)
		}
		length, err := AddressLength(destination)
		if err != nil {
			t.Fatalf("AddressLength(%s): %v", domain, err)
		}
		if buffer.Len() != length {
			t.Fatalf("AddressLength(%s) = %d, encoded %d", domain, length, buffer.Len())
		}
		decoded, err := ReadAddress(&buffer)
		if err != nil {
			t.Fatalf("ReadAddress(%s): %v", domain, err)
		}
		if decoded != destination {
			t.Fatalf("round trip %s -> %s", destination, decoded)
		}
	}
	for _, raw := range []string{"127.0.0.1:1", "[::1]:65535", "0.0.0.0:0"} {
		destination := M.ParseSocksaddr(raw)
		var buffer bytes.Buffer
		if err := WriteAddress(&buffer, destination); err != nil {
			t.Fatalf("WriteAddress(%s): %v", raw, err)
		}
		decoded, err := ReadAddress(&buffer)
		if err != nil {
			t.Fatalf("ReadAddress(%s): %v", raw, err)
		}
		if decoded != destination {
			t.Fatalf("round trip %s -> %s", destination, decoded)
		}
	}
}

func TestAddressErrors(t *testing.T) {
	// Truncated address type.
	if _, err := ReadAddress(bytes.NewReader(mustHex(t, "01"))); err == nil {
		t.Fatal("truncated IPv4 accepted")
	}
	// Truncated port.
	if _, err := ReadAddress(bytes.NewReader(mustHex(t, "017f00000246"))); err == nil {
		t.Fatal("truncated port accepted")
	}
	// Unknown address type.
	if _, err := ReadAddress(bytes.NewReader(mustHex(t, "0201020304"))); err == nil {
		t.Fatal("unknown address type accepted")
	}
	// Zero length domain.
	if _, err := ReadAddress(bytes.NewReader(mustHex(t, "03000050"))); err == nil {
		t.Fatal("empty domain accepted")
	}
	// Truncated domain body.
	if _, err := ReadAddress(bytes.NewReader(mustHex(t, "03056162634651"))); err == nil {
		t.Fatal("truncated domain accepted")
	}
	// Unsupported destination address.
	if err := WriteAddress(&bytes.Buffer{}, M.Socksaddr{}); err == nil {
		t.Fatal("empty destination accepted")
	}
	// Domain longer than 255 bytes.
	longDomain := M.Socksaddr{Fqdn: strings.Repeat("d", 256), Port: 443}
	if err := WriteAddress(&bytes.Buffer{}, longDomain); err == nil {
		t.Fatal("256 byte domain accepted")
	}
	// Frame longer than the reference receiver limit.
	channel := M.SocksaddrFrom(netip.MustParseAddr("0.0.0.0"), 0)
	if _, err := EncodeUDPFrame(channel, channel, make([]byte, MaxUDPBody)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	// Truncated frame body.
	frame := mustHex(t, "001b01000000000000017f00000246a444594e414d4943")
	if _, _, _, err := DecodeUDPFrame(bytes.NewReader(frame)); err == nil {
		t.Fatal("truncated frame accepted")
	}
}

func TestFrameLengths(t *testing.T) {
	channel := M.SocksaddrFrom(netip.MustParseAddr("0.0.0.0"), 0)
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.2"), 18084)
	for _, payloadLength := range []int{0, 1, 100, MaxUDPBody - 14} {
		payload := bytes.Repeat([]byte{0x41}, payloadLength)
		frame, err := EncodeUDPFrame(channel, destination, payload)
		if err != nil {
			t.Fatalf("EncodeUDPFrame(%d): %v", payloadLength, err)
		}
		if len(frame) != 2+14+payloadLength {
			t.Fatalf("frame length %d, want %d", len(frame), 2+14+payloadLength)
		}
		_, _, decoded, err := DecodeUDPFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("DecodeUDPFrame(%d): %v", payloadLength, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("payload mismatch at %d", payloadLength)
		}
	}
}
