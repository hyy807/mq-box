package heysocks

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

// Conn wraps an established HTTP/2 stream and applies the xstream framing:
// the header block plus the continuous AES-CTR stream on both directions.
//
// The first Write emits `H || padding || extra || IVSize || IV` followed by the
// encrypted stream; the first Read consumes the peer IV, which the reference
// kernel reads in band with io.ReadAtLeast.
type Conn struct {
	net.Conn
	key                    []byte
	headerHMAC             []byte
	extra                  []byte
	prefix                 []byte
	paddingMinimum         int
	paddingMaximum         int
	wireVariant            string
	readVariant            string
	debug                  func(format string, args ...any)
	writeStream            *Stream
	readStream             *Stream
	writeInitialized       bool
	readInitialized        bool
	skipFirstWriteDeadline bool
}

// NewConn builds the framing layer. prefix is the plaintext that must lead the
// stream (the destination address); it is encrypted together with the first
// payload.
func NewConn(conn net.Conn, key []byte, headerHMAC []byte, extra []byte, prefix []byte, paddingMinimum int, paddingMaximum int) *Conn {
	return NewConnWithOptions(conn, key, headerHMAC, extra, prefix, paddingMinimum, paddingMaximum,
		WireVariantDefault, ReadVariantIV, nil)
}

// NewConnWithOptions builds the framing layer with the diagnostic switches.
func NewConnWithOptions(conn net.Conn, key []byte, headerHMAC []byte, extra []byte, prefix []byte,
	paddingMinimum int, paddingMaximum int, wireVariant string, readVariant string,
	debug func(format string, args ...any)) *Conn {
	return &Conn{
		Conn:           conn,
		key:            key,
		headerHMAC:     headerHMAC,
		extra:          extra,
		prefix:         prefix,
		paddingMinimum: paddingMinimum,
		paddingMaximum: paddingMaximum,
		wireVariant:    wireVariant,
		readVariant:    readVariant,
		debug:          debug,
	}
}

func (c *Conn) debugf(format string, args ...any) {
	if c.debug != nil {
		c.debug(format, args...)
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	if !c.writeInitialized {
		if err := c.writeHeader(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	buffer := make([]byte, len(p))
	copy(buffer, p)
	c.writeStream.XORKeyStream(buffer)
	n, err := c.Conn.Write(buffer)
	if err != nil {
		return 0, err
	}
	if n != len(buffer) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *Conn) writeHeader(payload []byte) error {
	iv, err := RandomIV()
	if err != nil {
		return err
	}
	c.writeStream, err = NewStream(c.key, iv)
	if err != nil {
		return err
	}
	paddingLength, err := RandomPadding(c.paddingMinimum, c.paddingMaximum)
	if err != nil {
		return err
	}
	padding := make([]byte, paddingLength)
	if paddingLength > 0 {
		if _, err = rand.Read(padding); err != nil {
			return E.Cause(err, "heysocks: generate padding")
		}
	}
	body := make([]byte, 0, len(c.prefix)+len(payload))
	body = append(body, c.prefix...)
	body = append(body, payload...)
	c.writeStream.XORKeyStream(body)
	frame := HeaderBlockRandom(c.wireVariant, c.headerHMAC, padding, c.extra, iv, nil)
	frame = append(frame, body...)
	if c.debug != nil {
		c.debugf("xhttp wire out: variant=%s header=%d padding=%d extra=%d prefix=%d payload=%d bytes=%s",
			c.wireVariant, len(frame)-len(body), paddingLength, len(c.extra), len(c.prefix), len(payload),
			hexPreview(frame, 128))
	}
	if err = writeFull(c.Conn, frame); err != nil {
		return E.Cause(err, "heysocks: write header block")
	}
	c.writeInitialized = true
	return nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if !c.readInitialized {
		if err := c.readPeerBlock(); err != nil {
			return 0, err
		}
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.readStream.XORKeyStream(p[:n])
	}
	return n, err
}

// readPeerBlock consumes the peer's first block. The specification calls it
// homogeneous with ours (section 3.4), so the reader mirrors the writer's
// layout: 01 || P || padding || [extra] || H || random[128] || 0x10 || IV.
func (c *Conn) readPeerBlock() error {
	if c.wireVariant == WireVariantLegacy {
		if c.readVariant == ReadVariantHMACIV {
			hmac := make([]byte, HeaderHMACSize)
			if _, err := io.ReadFull(c.Conn, hmac); err != nil {
				return E.Cause(err, "heysocks: read peer H")
			}
			c.debugf("xhttp wire in: peer H=%s (expected %s)", hexPreview(hmac, 16), hexPreview(c.headerHMAC, 16))
			var sizeByte [1]byte
			if _, err := io.ReadFull(c.Conn, sizeByte[:]); err != nil {
				return E.Cause(err, "heysocks: read peer IV size")
			}
			c.debugf("xhttp wire in: peer IV size byte=%d", sizeByte[0])
		}
	} else {
		var prefix [2]byte
		if _, err := io.ReadFull(c.Conn, prefix[:]); err != nil {
			return E.Cause(err, "heysocks: read peer block prefix")
		}
		if prefix[0] != FrameMagic {
			return E.New("heysocks: unexpected frame magic ", prefix[0])
		}
		if paddingLength := int(prefix[1]); paddingLength > 0 {
			if _, err := io.ReadFull(c.Conn, make([]byte, paddingLength)); err != nil {
				return E.Cause(err, "heysocks: read peer padding")
			}
		}
		readHMAC := func() error {
			hmac := make([]byte, HeaderHMACSize)
			if _, err := io.ReadFull(c.Conn, hmac); err != nil {
				return E.Cause(err, "heysocks: read peer H")
			}
			if c.readVariant == ReadVariantHMACIV {
				c.debugf("xhttp wire in: peer H=%s (expected %s)", hexPreview(hmac, 16), hexPreview(c.headerHMAC, 16))
			}
			return nil
		}
		readRegion := func() error {
			if _, err := io.ReadFull(c.Conn, make([]byte, RandomRegionSize)); err != nil {
				return E.Cause(err, "heysocks: read peer random region")
			}
			return nil
		}
		readExtra := func() error {
			if len(c.extra) == 0 {
				return nil
			}
			if _, err := io.ReadFull(c.Conn, make([]byte, len(c.extra))); err != nil {
				return E.Cause(err, "heysocks: read peer extra")
			}
			return nil
		}
		switch c.wireVariant {
		case WireVariantRandSeparated:
			if err := readHMAC(); err != nil {
				return err
			}
			if err := readRegion(); err != nil {
				return err
			}
			if err := readExtra(); err != nil {
				return err
			}
		case WireVariantNoExtra:
			if err := readHMAC(); err != nil {
				return err
			}
			if err := readRegion(); err != nil {
				return err
			}
		default:
			if err := readExtra(); err != nil {
				return err
			}
			if err := readHMAC(); err != nil {
				return err
			}
			if err := readRegion(); err != nil {
				return err
			}
		}
		var sizeByte [1]byte
		if _, err := io.ReadFull(c.Conn, sizeByte[:]); err != nil {
			return E.Cause(err, "heysocks: read peer IV size")
		}
		if sizeByte[0] != IVSize {
			return E.New("heysocks: unexpected peer IV size ", sizeByte[0])
		}
		if c.readVariant == ReadVariantHMACIV {
			c.debugf("xhttp wire in: peer IV size byte=%d", sizeByte[0])
		}
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return E.Cause(err, "heysocks: read peer IV")
	}
	c.debugf("xhttp wire in: read variant=%s peer IV=%s", c.readVariant, hexPreview(iv, 16))
	var err error
	c.readStream, err = NewStream(c.key, iv)
	if err != nil {
		return err
	}
	c.readInitialized = true
	return nil
}

func (c *Conn) NeedHandshakeForRead() bool  { return !c.readInitialized }
func (c *Conn) NeedHandshakeForWrite() bool { return !c.writeInitialized }
func (c *Conn) ReaderReplaceable() bool     { return c.readInitialized }
func (c *Conn) WriterReplaceable() bool     { return c.writeInitialized }
func (c *Conn) Upstream() any               { return c.Conn }

// FrontHeadroom keeps the plain writer path: the header block is emitted by
// Write, so no caller-visible headroom is required.
func (c *Conn) FrontHeadroom() int { return 0 }

// NeedAdditionalReadDeadline matches the reference behaviour of reading the peer
// IV before the first payload.
func (c *Conn) NeedAdditionalReadDeadline() bool { return true }

func hexPreview(data []byte, limit int) string {
	if len(data) > limit {
		return hex.EncodeToString(data[:limit]) + "...(" + itoa(len(data)) + ")"
	}
	return hex.EncodeToString(data)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
