// Package lightxtreme implements the opt-in LightXtreme AnyTLS authentication.
// Framing, padding, multiplexing and session lifecycle remain in sing-anytls.
package lightxtreme

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"time"
)

// DefaultPlatformMarker is the observed Linux marker. The vendor's iOS marker
// is unknown; callers can explicitly select another marker in their config.
const DefaultPlatformMarker uint8 = 3

type timestampCache struct {
	sync.Mutex
	initialized bool
	first       int64
}

var processTimestamps timestampCache

// Auth is evaluated once per outbound construction, never once per connection.
func Auth(password string, marker uint8) [32]byte {
	return processTimestamps.auth(password, marker, func() int64 { return time.Now().UnixMilli() })
}

func (c *timestampCache) auth(password string, marker uint8, now func() int64) [32]byte {
	if len(password) != 32 {
		return sha256.Sum256([]byte(password))
	}
	p, err := hex.DecodeString(password)
	if err != nil {
		return sha256.Sum256([]byte(password))
	}
	if marker == 0 {
		marker = DefaultPlatformMarker
	}
	c.Lock()
	t1 := now()
	if !c.initialized {
		c.first, c.initialized = t1, true
	}
	t0 := c.first
	c.Unlock()
	var stamp [16]byte
	binary.BigEndian.PutUint64(stamp[:8], uint64(t0)*10+uint64(marker))
	binary.BigEndian.PutUint64(stamp[8:], uint64(t1))
	var auth [32]byte
	copy(auth[:16], p)
	for i := range p {
		auth[16+i] = p[i] ^ stamp[i]
	}
	return auth
}

// WrapAuth replaces only the first 32 plaintext bytes written to a fresh TLS
// connection. sing-anytls currently writes AUTH+padding in its first Write.
// Tracking accepted bytes also makes split/short writes safe. No caller-owned
// buffer is mutated; subsequent framing is passed through unchanged.
func WrapAuth(conn net.Conn, auth [32]byte) net.Conn {
	return &authConn{Conn: conn, auth: auth}
}

type authConn struct {
	net.Conn
	access  sync.Mutex
	auth    [32]byte
	written int
}

func (c *authConn) Write(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.written >= len(c.auth) {
		return c.Conn.Write(p)
	}
	replacement := append([]byte(nil), p...)
	count := min(len(p), len(c.auth)-c.written)
	copy(replacement[:count], c.auth[c.written:c.written+count])
	n, err := c.Conn.Write(replacement)
	c.written += min(n, count)
	return n, err
}
