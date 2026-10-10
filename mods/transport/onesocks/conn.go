package onesocks

import (
	"bytes"
	"crypto/cipher"
	"io"
	"net"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Conn is the OneSocks stream: the request block and the destination address
// are written once by Dial, writes are encrypted with the outbound CTR stream,
// and the server block is read lazily on the first Read so neither side waits
// for the other.
type Conn struct {
	net.Conn
	key         []byte
	hmac        []byte
	writeStream cipher.Stream
	readStream  cipher.Stream
	writeAccess sync.Mutex
	readAccess  sync.Mutex
	blockRead   bool
}

// Dial writes 01||P||padding||H||0x10||IV followed by the encrypted destination
// address and returns the stream wrapper. It never waits for the server block:
// the reference server only answers once the client has sent payload, so
// blocking here would deadlock both sides.
func Dial(rawConn net.Conn, key []byte, hmac []byte, paddingRange PaddingRange, destination M.Socksaddr) (*Conn, error) {
	iv, err := RandomIV()
	if err != nil {
		return nil, err
	}
	stream, err := NewCTR(key, iv)
	if err != nil {
		return nil, err
	}
	header, err := BuildHeader(hmac, paddingRange.Pick(), iv)
	if err != nil {
		return nil, err
	}
	plainAddress, err := WriteAddress(nil, destination)
	if err != nil {
		return nil, err
	}
	encryptedAddress := make([]byte, len(plainAddress))
	stream.XORKeyStream(encryptedAddress, plainAddress)
	request := make([]byte, 0, len(header)+len(encryptedAddress))
	request = append(request, header...)
	request = append(request, encryptedAddress...)
	if _, err = rawConn.Write(request); err != nil {
		return nil, E.Cause(err, "onesocks: write request block")
	}
	return &Conn{
		Conn:        rawConn,
		key:         key,
		hmac:        hmac,
		writeStream: stream,
	}, nil
}

func (c *Conn) Read(buffer []byte) (int, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if !c.blockRead {
		if err := c.readBlock(); err != nil {
			return 0, err
		}
	}
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.readStream.XORKeyStream(buffer[:n], buffer[:n])
	}
	return n, err
}

func (c *Conn) Write(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	encrypted := make([]byte, len(buffer))
	c.writeStream.XORKeyStream(encrypted, buffer)
	if _, err := c.Conn.Write(encrypted); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

// readBlock consumes 01 || P || padding || H || 0x10 || IV from the server.
func (c *Conn) readBlock() error {
	var head [2]byte
	if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
		return E.Cause(err, "onesocks: read response magic")
	}
	if head[0] != FrameMagic {
		return E.New("onesocks: unexpected response magic ", head[0])
	}
	padding := int(head[1])
	rest := make([]byte, padding+HeaderHMACSize+1+IVSize)
	if _, err := io.ReadFull(c.Conn, rest); err != nil {
		return E.Cause(err, "onesocks: read response block")
	}
	responseHMAC := rest[padding : padding+HeaderHMACSize]
	if !bytes.Equal(responseHMAC, c.hmac) {
		return E.New("onesocks: response hmac mismatch")
	}
	ivLength := rest[padding+HeaderHMACSize]
	if int(ivLength) != IVSize {
		return E.New("onesocks: unexpected response iv length ", ivLength)
	}
	iv := rest[padding+HeaderHMACSize+1 : padding+HeaderHMACSize+1+IVSize]
	stream, err := NewCTR(c.key, iv)
	if err != nil {
		return err
	}
	c.readStream = stream
	c.blockRead = true
	return nil
}
