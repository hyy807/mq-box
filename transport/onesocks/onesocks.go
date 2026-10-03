// Package onesocks implements the Heysocks `type: os` (OneSocks) data plane: a
// plain TCP stream whose first block, in both directions, is
//
//	01 || P:u8 || random_padding[P] || H[16] || 0x10 || IV[16] || ciphertext
//
// with
//
//	H         = MD5(password || "_onesocks")
//	K         = MD5 chain over the raw password bytes
//	plaintext = SOCKS_ADDR(destination) || payload
//
// Each direction announces its own random IV in band and keeps one continuous
// AES-CTR counter, which is never reset between writes.
//
// The salt differs from Heysocks xstream ("do not hack this protocol please");
// the two constants are not interchangeable.
package onesocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net/netip"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	// ProtocolSalt is the OneSocks KDF/MAC suffix.
	ProtocolSalt = "_onesocks"

	// IVSize is the AES-CTR IV length announced in the header block.
	IVSize = 16

	// HeaderHMACSize is the length of H.
	HeaderHMACSize = 16

	// FrameMagic is the first byte of the request and response blocks.
	FrameMagic = 0x01
)

// cipherKeySize maps the reference algorithm table to key sizes. Only the CTR
// family is exercised by the reference clients.
var cipherKeySize = map[string]int{
	"AES-128-CTR": 16,
	"AES-192-CTR": 24,
	"AES-256-CTR": 32,
}

// CipherKeySize resolves an algorithm name to its key length. An empty name
// defaults to AES-128-CTR, matching the reference nodes.
func CipherKeySize(cipherName string) (int, error) {
	name := strings.ToUpper(strings.TrimSpace(cipherName))
	if name == "" {
		name = "AES-128-CTR"
	}
	keySize, loaded := cipherKeySize[name]
	if !loaded {
		return 0, E.New("onesocks: unsupported cipher ", cipherName)
	}
	return keySize, nil
}

// Kdf derives keySize bytes with the MD5 chain D0 = empty, Di = MD5(D(i-1) || seed).
func Kdf(seed []byte, keySize int) []byte {
	key := make([]byte, 0, keySize+md5.Size)
	var previous []byte
	for len(key) < keySize {
		hash := md5.New()
		hash.Write(previous)
		hash.Write(seed)
		previous = hash.Sum(nil)
		key = append(key, previous...)
	}
	return key[:keySize]
}

// PasswordKey derives the stream key. The password is used as raw bytes, never
// hex decoded.
func PasswordKey(password string, keySize int) []byte {
	return Kdf([]byte(password), keySize)
}

// PasswordHMAC is H: the raw 16 bytes of MD5(password || "_onesocks").
func PasswordHMAC(password string) []byte {
	sum := md5.Sum([]byte(password + ProtocolSalt))
	return sum[:]
}

// NewCTR builds the AES-CTR stream for one direction.
func NewCTR(key []byte, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E.Cause(err, "onesocks: aes cipher")
	}
	if len(iv) != IVSize {
		return nil, E.New("onesocks: invalid iv length ", len(iv))
	}
	return cipher.NewCTR(block, iv), nil
}

// RandomIV returns a fresh 16 byte IV.
func RandomIV() ([]byte, error) {
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, E.Cause(err, "onesocks: generate iv")
	}
	return iv, nil
}

// PaddingRange is the inclusive lower / exclusive upper padding window. The
// reference "8-64" therefore yields 8..63 bytes.
type PaddingRange struct {
	Min int
	Max int
}

// ParsePadding parses "min-max". An empty or degenerate window means no padding.
func ParsePadding(spec string) (PaddingRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PaddingRange{}, nil
	}
	if !strings.Contains(spec, "-") {
		return PaddingRange{}, E.New("onesocks: padding must look like xx-xx")
	}
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return PaddingRange{}, E.New("onesocks: padding must look like xx-xx")
	}
	min, minErr := strconv.Atoi(strings.TrimSpace(parts[0]))
	if minErr != nil {
		return PaddingRange{}, E.Cause(minErr, "onesocks: padding minimum")
	}
	max, maxErr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if maxErr != nil {
		return PaddingRange{}, E.Cause(maxErr, "onesocks: padding maximum")
	}
	if min < 0 || max > 255 {
		return PaddingRange{}, E.New("onesocks: padding bounds out of range: ", spec)
	}
	if max-min <= 0 {
		return PaddingRange{}, nil
	}
	return PaddingRange{Min: min, Max: max}, nil
}

// Pick returns a random padding length inside the window.
func (r PaddingRange) Pick() int {
	if r.Max-r.Min <= 0 {
		return 0
	}
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return r.Min
	}
	return r.Min + int(binary.BigEndian.Uint32(raw[:])%uint32(r.Max-r.Min))
}

// BuildHeader returns 01 || P || padding || H || 0x10 || IV.
func BuildHeader(hmac []byte, padding int, iv []byte) ([]byte, error) {
	if len(hmac) != HeaderHMACSize {
		return nil, E.New("onesocks: invalid hmac length ", len(hmac))
	}
	if len(iv) != IVSize {
		return nil, E.New("onesocks: invalid iv length ", len(iv))
	}
	if padding < 0 || padding > 255 {
		return nil, E.New("onesocks: invalid padding length ", padding)
	}
	header := make([]byte, 0, 2+padding+HeaderHMACSize+1+IVSize)
	header = append(header, FrameMagic, byte(padding))
	if padding > 0 {
		randomPadding := make([]byte, padding)
		if _, err := rand.Read(randomPadding); err != nil {
			return nil, E.Cause(err, "onesocks: padding")
		}
		header = append(header, randomPadding...)
	}
	header = append(header, hmac...)
	header = append(header, byte(IVSize))
	header = append(header, iv...)
	return header, nil
}

// Address types of the OneSocks destination address:
//
//	IPv4   : 01 || IP[4]  big endian || port BE16
//	IPv6   : 04 || IP[16] big endian || port BE16
//	domain : 03 || len:u8 || domain    || port BE16
const (
	AddressTypeIPv4   byte = 0x01
	AddressTypeDomain byte = 0x03
	AddressTypeIPv6   byte = 0x04
)

// WriteAddress appends the destination address to buffer.
func WriteAddress(buffer []byte, destination M.Socksaddr) ([]byte, error) {
	switch {
	case destination.IsIPv4():
		buffer = append(buffer, AddressTypeIPv4)
		address := destination.Addr.As4()
		buffer = append(buffer, address[:]...)
	case destination.IsIPv6():
		buffer = append(buffer, AddressTypeIPv6)
		address := destination.Addr.As16()
		buffer = append(buffer, address[:]...)
	case destination.IsFqdn():
		domain := destination.Fqdn
		if len(domain) == 0 || len(domain) > 255 {
			return nil, E.New("onesocks: invalid domain length ", len(domain))
		}
		buffer = append(buffer, AddressTypeDomain, byte(len(domain)))
		buffer = append(buffer, domain...)
	default:
		return nil, E.New("onesocks: unsupported destination address")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], destination.Port)
	buffer = append(buffer, port[:]...)
	return buffer, nil
}

// AddressLength reports the encoded length for the destination.
func AddressLength(destination M.Socksaddr) (int, error) {
	switch {
	case destination.IsIPv4():
		return 7, nil
	case destination.IsIPv6():
		return 19, nil
	case destination.IsFqdn():
		length := len(destination.Fqdn)
		if length == 0 || length > 255 {
			return 0, E.New("onesocks: invalid domain length ", length)
		}
		return 1 + 1 + length + 2, nil
	default:
		return 0, E.New("onesocks: unsupported destination address")
	}
}

// ReadAddress decodes a destination address; used by the fake server in tests.
func ReadAddress(reader io.Reader) (M.Socksaddr, error) {
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "onesocks: read address type")
	}
	switch addressType[0] {
	case AddressTypeIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "onesocks: read IPv4 address")
		}
		return finishAddress(reader, M.Socksaddr{Addr: netip.AddrFrom4(raw)})
	case AddressTypeIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "onesocks: read IPv6 address")
		}
		return finishAddress(reader, M.Socksaddr{Addr: netip.AddrFrom16(raw)})
	case AddressTypeDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return M.Socksaddr{}, E.Cause(err, "onesocks: read domain length")
		}
		if length[0] == 0 {
			return M.Socksaddr{}, E.New("onesocks: empty domain")
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(reader, domain); err != nil {
			return M.Socksaddr{}, E.Cause(err, "onesocks: read domain")
		}
		return finishAddress(reader, M.Socksaddr{Fqdn: strings.ToLower(string(domain))})
	default:
		return M.Socksaddr{}, E.New("onesocks: unknown address type ", addressType[0])
	}
}

func finishAddress(reader io.Reader, address M.Socksaddr) (M.Socksaddr, error) {
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return M.Socksaddr{}, E.Cause(err, "onesocks: read port")
	}
	address.Port = binary.BigEndian.Uint16(port[:])
	return address, nil
}
