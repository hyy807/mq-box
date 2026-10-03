// Package heysocks implements the Heysocks xstream data plane: the AES-CTR
// stream cipher with the MD5 chain KDF and the connection header block.
//
// Layout recovered from the reference kernel symbols (spec section 4):
//
//	key   = Kdf(seed, keySize)                       // MD5 chain, seed is ASCII
//	H     = MD5(seed + "do not hack this protocol please")
//	extra = hex_decode(parts[1])
//	header = H(16) || padding(P) || extra || 0x10 || IV(16)
//
// followed by the continuous AES-CTR stream in both directions, each direction
// with its own random IV.
package heysocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// ProtocolSalt is the Heysocks KDF/MAC suffix. It differs from the OneSocks
	// constant ("_onesocks"); do not interchange them.
	ProtocolSalt = "do not hack this protocol please"

	// IVSize is the AES-CTR IV length reported in the header block.
	IVSize = 16

	// HeaderHMACSize is the length of H.
	HeaderHMACSize = 16

	// FrameMagic leads the first block: 01 || P || padding || … (spec section 3.2).
	FrameMagic byte = 0x01
)

// cipherKeySize maps the reference algorithm table to key sizes. Only the CTR
// family is implemented: the CFB names appear in the table but were never
// exercised by the reference clients.
var cipherKeySize = map[string]int{
	"AES-128-CTR": 16,
	"AES-192-CTR": 24,
	"AES-256-CTR": 32,
}

// Kdf derives keySize bytes with the MD5 chain: D0 = empty, Di = MD5(D(i-1) || seed).
func Kdf(seed string, keySize int) []byte {
	key := make([]byte, 0, keySize)
	var previous []byte
	for len(key) < keySize {
		hash := md5.New()
		hash.Write(previous)
		hash.Write([]byte(seed))
		previous = hash.Sum(nil)
		key = append(key, previous...)
	}
	return key[:keySize]
}

// HeaderHMAC returns H = MD5(seed ++ ProtocolSalt).
func HeaderHMAC(seed string) []byte {
	sum := md5.Sum([]byte(seed + ProtocolSalt))
	return sum[:]
}

// ParsePassword splits "seed:extra" and returns the ASCII seed, the decoded
// extra bytes and the derived key for the requested cipher.
func ParsePassword(cipherName string, password string) (seed string, extra []byte, key []byte, err error) {
	parts := strings.Split(password, ":")
	if len(parts) != 2 {
		return "", nil, nil, E.New("heysocks: password must be \"<seed>:<extra>\"")
	}
	seed = parts[0]
	if seed == "" {
		return "", nil, nil, E.New("heysocks: empty seed")
	}
	extra, err = hex.DecodeString(parts[1])
	if err != nil {
		return "", nil, nil, E.Cause(err, "heysocks: decode extra")
	}
	keySize, err := CipherKeySize(cipherName)
	if err != nil {
		return "", nil, nil, err
	}
	return seed, extra, Kdf(seed, keySize), nil
}

// CipherKeySize resolves the cipher name; the empty result key size means the
// DUMMY cipher (no encryption).
func CipherKeySize(cipherName string) (int, error) {
	name := strings.ToUpper(cipherName)
	if name == "" {
		name = "AES-128-CTR"
	}
	if name == "DUMMY" {
		return 0, nil
	}
	keySize, loaded := cipherKeySize[name]
	if !loaded {
		return 0, E.New("heysocks: unsupported cipher ", cipherName, " (only AES-*-CTR and DUMMY are implemented)")
	}
	return keySize, nil
}

// PaddingRange parses "min-max". The upper bound is exclusive, matching
// parsePaddingLen of the reference kernel.
func PaddingRange(value string) (int, int, error) {
	if value == "" {
		return 0, 0, nil
	}
	if !strings.Contains(value, "-") {
		return 0, 0, E.New("heysocks: padding_len must be like xx-xx, max must less equal 255")
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, E.New("heysocks: padding_len must be like xx-xx, max must less equal 255")
	}
	minimum, err := parseInt(parts[0])
	if err != nil {
		return 0, 0, E.Cause(err, "heysocks: padding minimum")
	}
	maximum, err := parseInt(parts[1])
	if err != nil {
		return 0, 0, E.Cause(err, "heysocks: padding maximum")
	}
	if minimum < 0 || maximum < 0 || maximum > 255 || minimum > maximum {
		return 0, 0, E.New("heysocks: padding_len must be like xx-xx, max must less equal 255")
	}
	return minimum, maximum, nil
}

func parseInt(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, E.New("empty number")
	}
	result := 0
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, E.New("invalid number ", value)
		}
		result = result*10 + int(digit-'0')
		if result > 1<<20 {
			return 0, E.New("number too large")
		}
	}
	return result, nil
}

// RandomPadding returns the padding length for one frame: min + rand.Intn(max-min),
// and 0 when the window is empty.
func RandomPadding(minimum int, maximum int) (int, error) {
	span := maximum - minimum
	if span <= 0 {
		return 0, nil
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	return minimum + int(value.Int64()), nil
}

// Stream is one direction of the AES-CTR state. The counter never resets while
// the connection lives.
type Stream struct {
	stream cipher.Stream
}

// NewStream builds the CTR state for an IV.
func NewStream(key []byte, iv []byte) (*Stream, error) {
	if len(key) == 0 {
		return &Stream{}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E.Cause(err, "heysocks: create AES cipher")
	}
	if len(iv) != IVSize {
		return nil, E.New("heysocks: IV must be ", IVSize, " bytes, got ", len(iv))
	}
	return &Stream{stream: cipher.NewCTR(block, iv)}, nil
}

// XORKeyStream encrypts or decrypts in place, continuing the counter.
func (s *Stream) XORKeyStream(destination []byte) {
	if s.stream == nil {
		return
	}
	s.stream.XORKeyStream(destination, destination)
}

// RandomIV returns a fresh IV.
func RandomIV() ([]byte, error) {
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, E.Cause(err, "heysocks: generate IV")
	}
	return iv, nil
}

// Header block layouts.
//
// The reference clients reserve a 128 byte random region between H and the
// IV-size byte: their disassembly writes 0x10 at offset 0x90 = 16 (H) + 128,
// and sizes the first-block buffer as extra + 0xa1 = extra + 16 + 128 + 1 + 16.
// The relative order of `extra` is the one item the specification still marks
// as inferred, so the layouts stay switchable.
const (
	// RandomRegionSize is the fixed random region both reference clients send.
	RandomRegionSize = 0x80

	// WireVariantDefault: 01 || P || padding || extra || H || random[128] || 0x10 || IV
	// (the extra placement that matches the reference buffer arithmetic).
	WireVariantDefault = "default"
	// WireVariantRandSeparated: 01 || P || padding || H || random[128] || extra || 0x10 || IV
	WireVariantRandSeparated = "rand-separated"
	// WireVariantNoExtra: 01 || P || padding || H || random[128] || 0x10 || IV
	// (the literal reading of the specification diagram, extra omitted).
	WireVariantNoExtra = "no-extra"
	// WireVariantLegacy: H || padding || extra || 0x10 || IV, the first guess
	// without the magic, the padding length byte or the random region.
	WireVariantLegacy = "legacy"
)

// NormalizeWireVariant validates the diagnostic switch.
func NormalizeWireVariant(value string) (string, error) {
	switch value {
	case "", WireVariantDefault:
		return WireVariantDefault, nil
	case WireVariantRandSeparated, WireVariantNoExtra, WireVariantLegacy:
		return value, nil
	default:
		return "", E.New("heysocks: unknown wire_variant ", value)
	}
}

// HeaderBlock builds the connection header with the default (spec aligned)
// layout and a fresh random region, for tests and callers without switches.
func HeaderBlock(headerHMAC []byte, padding []byte, extra []byte, iv []byte) []byte {
	return HeaderBlockRandom(WireVariantDefault, headerHMAC, padding, extra, iv, nil)
}

// HeaderBlockRandom builds one layout. randomRegion is filled by the caller when
// a deterministic vector is needed; nil means "generate random bytes".
func HeaderBlockRandom(variant string, headerHMAC []byte, padding []byte, extra []byte, iv []byte, randomRegion []byte) []byte {
	if variant == WireVariantLegacy {
		block := make([]byte, 0, len(headerHMAC)+len(padding)+len(extra)+1+len(iv))
		block = append(block, headerHMAC...)
		block = append(block, padding...)
		block = append(block, extra...)
		block = append(block, byte(IVSize))
		block = append(block, iv...)
		return block
	}
	region := randomRegion
	if region == nil {
		region = make([]byte, RandomRegionSize)
		if _, err := rand.Read(region); err != nil {
			region = make([]byte, RandomRegionSize)
		}
	}
	block := make([]byte, 0, 2+len(padding)+len(extra)+len(headerHMAC)+RandomRegionSize+1+len(iv))
	block = append(block, FrameMagic, byte(len(padding)))
	block = append(block, padding...)
	switch variant {
	case WireVariantRandSeparated:
		block = append(block, headerHMAC...)
		block = append(block, region...)
		block = append(block, extra...)
	case WireVariantNoExtra:
		block = append(block, headerHMAC...)
		block = append(block, region...)
	default:
		block = append(block, extra...)
		block = append(block, headerHMAC...)
		block = append(block, region...)
	}
	block = append(block, byte(IVSize))
	block = append(block, iv...)
	return block
}

// Read variants for the downstream direction.
const (
	ReadVariantIV     = "iv"
	ReadVariantHMACIV = "hmac-iv"
)

// NormalizeReadVariant validates the diagnostic switch.
func NormalizeReadVariant(value string) (string, error) {
	switch value {
	case "", ReadVariantIV:
		return ReadVariantIV, nil
	case ReadVariantHMACIV:
		return ReadVariantHMACIV, nil
	default:
		return "", E.New("heysocks: unknown read_variant ", value)
	}
}
