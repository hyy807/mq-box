package heysocks

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// Byte aligned with serializesSocksAddr (RVA 0x6fe1e0):
// 01 || IP[4] || port BE16, 04 || IP[16] || port BE16, 03 || len || domain || port BE16.
func TestWriteAddressVectors(t *testing.T) {
	testCases := []struct {
		name        string
		destination M.Socksaddr
		expected    string
		length      int
	}{
		{
			name:        "ipv4",
			destination: M.SocksaddrFrom(netip.MustParseAddr("1.2.3.4"), 443),
			expected:    "010102030401bb",
			length:      7,
		},
		{
			name:        "ipv4 low port",
			destination: M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 80),
			expected:    "017f0000010050",
			length:      7,
		},
		{
			name:        "ipv6",
			destination: M.SocksaddrFrom(netip.MustParseAddr("::1"), 53),
			expected:    "04" + "00000000000000000000000000000001" + "0035",
			length:      19,
		},
		{
			name:        "domain",
			destination: M.Socksaddr{Fqdn: "www.example.com", Port: 8080},
			expected:    "030f" + hex.EncodeToString([]byte("www.example.com")) + "1f90",
			length:      1 + 1 + 15 + 2,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			buffer, err := WriteAddress(nil, testCase.destination)
			if err != nil {
				t.Fatalf("WriteAddress: %v", err)
			}
			if hex.EncodeToString(buffer) != testCase.expected {
				t.Fatalf("wire = %s, want %s", hex.EncodeToString(buffer), testCase.expected)
			}
			length, err := AddressLength(testCase.destination)
			if err != nil {
				t.Fatalf("AddressLength: %v", err)
			}
			if length != testCase.length || length != len(buffer) {
				t.Fatalf("length = %d (buffer %d), want %d", length, len(buffer), testCase.length)
			}
			// The port must come last, unlike the VMess address format.
			decoded, err := ReadAddress(bytes.NewReader(buffer))
			if err != nil {
				t.Fatalf("ReadAddress: %v", err)
			}
			if decoded.Port != testCase.destination.Port {
				t.Fatalf("port = %d, want %d", decoded.Port, testCase.destination.Port)
			}
			if decoded.IsFqdn() && decoded.Fqdn != testCase.destination.Fqdn {
				t.Fatalf("domain = %q", decoded.Fqdn)
			}
			if decoded.IsIP() && decoded.Addr != testCase.destination.Addr {
				t.Fatalf("address = %s", decoded.Addr)
			}
		})
	}
}

// The VMess serializer writes the port first and uses 02 for domains; if this
// test ever fails the wrong serializer crept back in.
func TestAddressIsNotVMessFormat(t *testing.T) {
	buffer, err := WriteAddress(nil, M.Socksaddr{Fqdn: "apple.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if buffer[0] != AddressTypeDomain {
		t.Fatalf("first byte = %02x, want %02x (domain)", buffer[0], AddressTypeDomain)
	}
	if buffer[0] == 0x02 {
		t.Fatal("VMess domain type byte")
	}
	if bytes.Equal(buffer[:2], []byte{0x01, 0xbb}) {
		t.Fatal("port is written first, VMess style")
	}
	if M.ParseSocksaddr("apple.com:443").Port == 0 {
		t.Fatal("sanity")
	}
}
