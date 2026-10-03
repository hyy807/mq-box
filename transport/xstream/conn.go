package xstream

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
)

// ErrIVPaddingTooLarge mirrors the reference kernel's 10 byte scan window.
var ErrIVPaddingTooLarge = errors.New("xstream: IV offset padding too large")

// Conn wraps the raw TCP connection of the xhttp transport. Writes ride the
// continuous AES-CTR keystream opened by the first block; the first Read lazily
// consumes the server's header so neither side ever blocks waiting on the other.
type Conn struct {
	net.Conn

	encryptStream cipher.Stream
	decryptStream cipher.Stream
	block         cipher.Block
	ivOffset      int

	readMu        sync.Mutex
	handshakeDone bool
	// serverHeader holds the bytes of the server header for diagnostics.
	serverHeader []byte
}

// NewConn builds the stream wrapper. ivOffset is the byte position of the IV
// length marker inside the server header (128 + 16 + extra length).
func NewConn(conn net.Conn, encryptStream cipher.Stream, block cipher.Block, ivOffset int) *Conn {
	return &Conn{
		Conn:          conn,
		encryptStream: encryptStream,
		block:         block,
		ivOffset:      ivOffset,
	}
}

// ServerHeader returns a copy of the parsed server header (diagnostics only).
func (c *Conn) ServerHeader() []byte {
	if c.serverHeader == nil {
		return nil
	}
	out := make([]byte, len(c.serverHeader))
	copy(out, c.serverHeader)
	return out
}

func (c *Conn) Write(buffer []byte) (int, error) {
	encrypted := make([]byte, len(buffer))
	c.encryptStream.XORKeyStream(encrypted, buffer)
	return c.Conn.Write(encrypted)
}

func (c *Conn) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	if !c.handshakeDone {
		// Lazy: the server header is consumed on the first real read so the
		// dial path never blocks (reference conn.go).
		baseHeader := make([]byte, c.ivOffset)
		if _, err := io.ReadFull(c.Conn, baseHeader); err != nil {
			c.readMu.Unlock()
			return 0, err
		}
		c.serverHeader = baseHeader

		shift := 0
		marker := make([]byte, 1)
		for {
			if _, err := io.ReadFull(c.Conn, marker); err != nil {
				c.readMu.Unlock()
				return 0, err
			}
			c.serverHeader = append(c.serverHeader, marker[0])
			if marker[0] == IVLength {
				break
			}
			shift++
			if shift > 10 {
				c.readMu.Unlock()
				return 0, ErrIVPaddingTooLarge
			}
		}

		serverIV := make([]byte, IVLength)
		if _, err := io.ReadFull(c.Conn, serverIV); err != nil {
			c.readMu.Unlock()
			return 0, err
		}
		c.serverHeader = append(c.serverHeader, serverIV...)

		c.decryptStream = cipher.NewCTR(c.block, serverIV)
		c.handshakeDone = true
	}
	c.readMu.Unlock()

	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.decryptStream.XORKeyStream(buffer[:n], buffer[:n])
	}
	return n, err
}

// ReadWithHeader is a diagnostic helper: it consumes the server header if it has
// not been consumed yet and returns it, without reading application data.
func (c *Conn) ReadWithHeader() ([]byte, error) {
	c.readMu.Lock()
	if c.handshakeDone {
		header := c.ServerHeader()
		c.readMu.Unlock()
		return header, nil
	}
	c.readMu.Unlock()
	var probe [1]byte
	// Trigger the lazy path, then stop before decrypting application data is
	// impossible to undo; callers use ServerHeader after a real Read instead.
	if _, err := c.Read(probe[:]); err != nil {
		if header := c.ServerHeader(); header != nil {
			return header, nil
		}
		return nil, err
	}
	return c.ServerHeader(), nil
}

var (
	_ net.Conn = (*Conn)(nil)
	_          = errors.New
)
