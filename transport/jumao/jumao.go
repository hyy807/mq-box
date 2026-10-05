// Package jumao implements the 橘猫 (Jumao) provider protocol.
//
// The stream is stock shadowsocks aes-256-cfb: the same EVP_BytesToKey(MD5, ...)
// chain, the same address header and the same framing. The single difference is
// the first IV, which is a watermark carrying the account's node credentials:
//
//	R  = 4 random bytes
//	ts = LE32(unix seconds)                  // checked by the peer against real time
//	X  = LE32(CRC32(LE32(user_id) || R || ts || user_pass))
//	IV = R || (R XOR LE32(user_id)) || ts || X          // 16 bytes
//
// A random IV is silently dropped by the peer, which looks like a connection that
// carries no data, so the watermark is the whole authentication.
package jumao

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	// IVSize is the first-IV / watermark length.
	IVSize = aes.BlockSize
	// KeySize is the aes-256-cfb key length.
	KeySize = 32
)

// PasswordKey derives the shadowsocks master key: MD5 chains the password into
// as many bytes as the cipher needs.
func PasswordKey(password string) []byte {
	var key []byte
	var previous []byte
	for len(key) < KeySize {
		hash := md5.New()
		hash.Write(previous)
		hash.Write([]byte(password))
		previous = hash.Sum(nil)
		key = append(key, previous...)
	}
	return key[:KeySize]
}

// WatermarkIV builds the 16 byte first IV. randomValue and unixSeconds are
// parameters so the layout can be pinned by a byte-exact test.
func WatermarkIV(userID uint32, userPass string, randomValue []byte, unixSeconds uint32) []byte {
	if len(randomValue) < 4 {
		panic("jumao: watermark needs 4 random bytes")
	}
	credential := make([]byte, 4)
	binary.LittleEndian.PutUint32(credential, userID)
	iv := make([]byte, IVSize)
	copy(iv[0:4], randomValue[:4])
	for i := 0; i < 4; i++ {
		iv[4+i] = randomValue[i] ^ credential[i]
	}
	binary.LittleEndian.PutUint32(iv[8:12], unixSeconds)
	checksum := crc32.NewIEEE()
	checksum.Write(credential)
	checksum.Write(randomValue[:4])
	checksum.Write(iv[8:12])
	checksum.Write([]byte(userPass))
	binary.LittleEndian.PutUint32(iv[12:16], checksum.Sum32())
	return iv
}

// NewWatermarkIV generates a watermark for the current second.
func NewWatermarkIV(userID uint32, userPass string) ([]byte, error) {
	randomValue := make([]byte, 4)
	if _, err := rand.Read(randomValue); err != nil {
		return nil, E.Cause(err, "jumao: cannot generate watermark")
	}
	return WatermarkIV(userID, userPass, randomValue, uint32(time.Now().Unix())), nil
}

// EncodeAddr is the shadowsocks address header: ATYP || address || BE16 port.
// The provider documents IPv4 and domain names; IPv6 is refused instead of
// emitting an address the peer never accepts.
func EncodeAddr(destination M.Socksaddr) ([]byte, error) {
	var header []byte
	switch {
	case destination.IsFqdn():
		fqdn := destination.Fqdn
		if len(fqdn) == 0 || len(fqdn) > 255 {
			return nil, E.New("jumao: invalid domain name")
		}
		header = append([]byte{3, byte(len(fqdn))}, fqdn...)
	case destination.Addr.Is4():
		address := destination.Addr.As4()
		header = append([]byte{1}, address[:]...)
	default:
		return nil, E.New("jumao: only IPv4 and domain destinations are supported")
	}
	return binary.BigEndian.AppendUint16(header, destination.Port), nil
}

// Conn is one jumao stream. Writes are encrypted with the watermark IV; the peer
// prepends its own IV to the first response, which is consumed on first read.
type Conn struct {
	net.Conn
	block cipher.Block
	enc   cipher.Stream
	dec   cipher.Stream
}

func (c *Conn) Write(p []byte) (int, error) {
	encrypted := make([]byte, len(p))
	c.enc.XORKeyStream(encrypted, p)
	return c.Conn.Write(encrypted)
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.dec == nil {
		iv := make([]byte, IVSize)
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			return 0, E.Cause(err, "jumao: reading the peer IV")
		}
		c.dec = cipher.NewCFBDecrypter(c.block, iv)
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// PeerIV reports whether the peer's IV was consumed, which is the first proof
// that the node accepted the watermark.
func (c *Conn) PeerIV() bool {
	return c.dec != nil
}

// Handshake writes IV || CFB(address header) and returns the ready stream.
// Ownership of rawConn transfers to the returned connection.
func Handshake(rawConn net.Conn, password string, userID uint32, userPass string, destination M.Socksaddr) (net.Conn, error) {
	key := PasswordKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E.Cause(err, "jumao: create cipher")
	}
	iv, err := NewWatermarkIV(userID, userPass)
	if err != nil {
		return nil, err
	}
	header, err := EncodeAddr(destination)
	if err != nil {
		return nil, err
	}
	encrypter := cipher.NewCFBEncrypter(block, iv)
	body := make([]byte, len(header))
	encrypter.XORKeyStream(body, header)
	if _, err = rawConn.Write(append(iv, body...)); err != nil {
		return nil, E.Cause(err, "jumao: send the watermarked header")
	}
	return &Conn{Conn: rawConn, block: block, enc: encrypter}, nil
}
