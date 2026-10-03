// Package xstream implements the first-block builder and stream framing of the
// Heysocks (just4test) raw-TCP xhttp protocol.
//
// The reference kernel (llyufenggotest/sing-box, protocol/xhttp) does NOT use
// TLS for this outbound. The outbound opens a plain TCP connection and sends:
//
//	[128 byte fake TCP header]      <- provider-supplied decoy, rest random
//	[16 byte H]                     <- MD5(part1_ascii + Salt)
//	[N byte raw HMAC key]           <- hex-decoded part2 of the password
//	[0x10]                          <- IV length marker (16)
//	[16 byte client IV]
//	[AES-CTR(destination address)]  <- same continuous keystream
//	[AES-CTR(payload) ...]
//
// The AES key is MD5(part1_ascii) (aes-128-ctr). The server reply mirrors the
// same header shape with its own fresh IV.
package xstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

// Salt is the constant suffix mixed into the header token. It is a literal
// string in the reference kernel (protocol/xhttp/outbound.go).
const Salt = "do not hack this protocol please"

// FakeHeaderLength is the size of the decoy TCP header region.
const FakeHeaderLength = 128

// IVLength is the AES-CTR IV size, and also the value written as the marker.
const IVLength = 16

// Config carries the per-node parameters recovered from the provider payload.
type Config struct {
	// Seed is the account-level token (part 1 of "password", ASCII).
	Seed string
	// ExtraHex is the per-node HMAC key (part 2 of "password", hex encoded).
	ExtraHex string
	// FakeTCPHex is the decoy TCP header (fake-net.tcp, hex encoded).
	FakeTCPHex string
}

// ParsePassword splits "<seed>:<hex>" and validates both halves.
func ParsePassword(password string) (seed string, extraHex string, err error) {
	seed, extraHex, found := strings.Cut(password, ":")
	if !found {
		return "", "", errors.New("xstream: password must be \"<seed>:<hex>\"")
	}
	seed = strings.TrimSpace(seed)
	extraHex = strings.TrimSpace(extraHex)
	if seed == "" {
		return "", "", errors.New("xstream: empty seed")
	}
	if _, err = hex.DecodeString(extraHex); err != nil {
		return "", "", fmt.Errorf("xstream: password key is not hex: %w", err)
	}
	return seed, extraHex, nil
}

// TokenHMAC returns H = MD5(seed + Salt).
func TokenHMAC(seed string) []byte {
	sum := md5.Sum([]byte(seed + Salt))
	return sum[:]
}

// Block returns the AES block derived from the seed (MD5(seed), 16 bytes).
func Block(seed string) (cipher.Block, error) {
	sum := md5.Sum([]byte(seed))
	return aes.NewCipher(sum[:])
}

// BuildFirstBlock assembles the opening flight and returns it together with the
// encryption stream that must be reused for every later Write on the same
// connection (CTR never resets).
func BuildFirstBlock(config Config, destination M.Socksaddr) (firstBlock []byte, encryptStream cipher.Stream, block cipher.Block, ivOffset int, err error) {
	extraKey, err := hex.DecodeString(config.ExtraHex)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("xstream: decode password key: %w", err)
	}
	extraLength := len(extraKey)

	// handshake = 128 fake + 16 H + extra + 1 marker + 16 IV
	handshakeLength := FakeHeaderLength + 16 + extraLength + 1 + IVLength
	ivOffset = FakeHeaderLength + 16 + extraLength

	handshake := make([]byte, handshakeLength)

	decoy, err := hex.DecodeString(config.FakeTCPHex)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("xstream: decode fake-net.tcp: %w", err)
	}
	copyLength := len(decoy)
	if copyLength > FakeHeaderLength {
		copyLength = FakeHeaderLength
	}
	copy(handshake[:copyLength], decoy[:copyLength])
	if copyLength < FakeHeaderLength {
		if _, err = rand.Read(handshake[copyLength:FakeHeaderLength]); err != nil {
			return nil, nil, nil, 0, err
		}
	}

	copy(handshake[FakeHeaderLength:FakeHeaderLength+16], TokenHMAC(config.Seed))
	copy(handshake[FakeHeaderLength+16:ivOffset], extraKey)

	handshake[ivOffset] = IVLength
	clientIV := handshake[ivOffset+1:]
	if _, err = rand.Read(clientIV); err != nil {
		return nil, nil, nil, 0, err
	}

	block, err = Block(config.Seed)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	encryptStream = cipher.NewCTR(block, clientIV)

	address, err := WriteAddress(destination)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	encryptedAddress := make([]byte, len(address))
	encryptStream.XORKeyStream(encryptedAddress, address)

	firstBlock = append(handshake, encryptedAddress...)
	return firstBlock, encryptStream, block, ivOffset, nil
}

// WriteAddress encodes a destination in SOCKS5 address form: the type byte
// leads, the port trails.
func WriteAddress(destination M.Socksaddr) ([]byte, error) {
	var buffer []byte
	switch {
	case destination.IsFqdn():
		host := destination.Fqdn
		if len(host) > 255 {
			return nil, errors.New("xstream: destination domain is too long")
		}
		buffer = make([]byte, 0, 2+len(host)+2)
		buffer = append(buffer, 0x03, byte(len(host)))
		buffer = append(buffer, host...)
	case destination.Addr.Is4():
		buffer = make([]byte, 0, 1+net.IPv4len+2)
		buffer = append(buffer, 0x01)
		buffer = append(buffer, destination.Addr.AsSlice()...)
	case destination.Addr.Is6():
		buffer = make([]byte, 0, 1+net.IPv6len+2)
		buffer = append(buffer, 0x04)
		buffer = append(buffer, destination.Addr.AsSlice()...)
	default:
		return nil, errors.New("xstream: unknown destination address family")
	}
	buffer = binary.BigEndian.AppendUint16(buffer, destination.Port)
	return buffer, nil
}
