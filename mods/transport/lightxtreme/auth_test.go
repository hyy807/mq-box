package lightxtreme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAuthVectors(t *testing.T) {
	for _, v := range []struct {
		marker   uint8
		second   int64
		expected string
	}{
		{3, 1791000755843, "00112233445566778899aabbccddeeff0011327abbf617568899ab1b332b507c"},
		{3, 1791000757155, "00112233445566778899aabbccddeeff0011327abbf617568899ab1b332b2d5c"},
		{1, 1791000755843, "00112233445566778899aabbccddeeff0011327abbf617688899ab1b332b507c"},
	} {
		c := timestampCache{initialized: true, first: 1791000755843}
		auth := c.auth("00112233445566778899AABBCCDDEEFF", v.marker, func() int64 { return v.second })
		if hex.EncodeToString(auth[:]) != v.expected {
			t.Fatalf("auth %x", auth)
		}
	}
}
func TestFallbackAndCache(t *testing.T) {
	var c timestampCache
	for _, p := range []string{"dummy-password", "zz112233445566778899aabbccddeeff", "00112233445566778899aabbccddee", ""} {
		if c.auth(p, 3, func() int64 { t.Fatal("fallback read clock"); return 0 }) != sha256.Sum256([]byte(p)) {
			t.Fatal("fallback")
		}
	}
	if c.initialized {
		t.Fatal("fallback initialized cache")
	}
	p := "00112233445566778899aabbccddeeff"
	a := c.auth(p, 0, func() int64 { return 100 })
	b := c.auth(p, 0, func() int64 { return 200 })
	if !bytes.Equal(a[16:24], b[16:24]) || bytes.Equal(a[24:], b[24:]) {
		t.Fatal("timestamp cache")
	}
	if c.first != 100 {
		t.Fatal("first changed")
	}
}
func TestConcurrentCache(t *testing.T) {
	var c timestampCache
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.auth("00112233445566778899aabbccddeeff", 3, func() int64 { return int64(i) })
		}(i)
	}
	wg.Wait()
	if !c.initialized {
		t.Fatal("uninitialized")
	}
}

type sinkConn struct {
	net.Conn
	bytes.Buffer
	limit int
}

func (c *sinkConn) Read(p []byte) (int, error) { return c.Buffer.Read(p) }

func (c *sinkConn) Write(p []byte) (int, error) {
	if c.limit > 0 && len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.Buffer.Write(p)
}
func TestSplitAndShortWrites(t *testing.T) {
	var auth [32]byte
	for i := range auth {
		auth[i] = byte(i + 1)
	}
	sink := &sinkConn{limit: 5}
	conn := WrapAuth(sink, auth)
	input := bytes.Repeat([]byte{0xee}, 70)
	original := bytes.Clone(input)
	for off := 0; off < len(input); {
		end := min(off+11, len(input))
		n, err := conn.Write(input[off:end])
		if err != nil || n == 0 {
			t.Fatal(n, err)
		}
		off += n
	}
	expected := append(auth[:], input[32:]...)
	if !bytes.Equal(sink.Bytes(), expected) || !bytes.Equal(input, original) {
		t.Fatal("write corruption")
	}
}

// Exercise the actual pinned sing-anytls client, not a synthetic handshake.
func TestPinnedClientHandshake(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "stock", true: "private"}[private], func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			_ = right.SetDeadline(time.Now().Add(3 * time.Second))
			password := "00112233445566778899aabbccddeeff"
			auth := (&timestampCache{}).auth(password, 3, func() int64 { return 1791000755843 })
			client, err := anytls.NewClient(anytls.ClientOptions{Password: password, DialOut: func(context.Context) (net.Conn, error) {
				if private {
					return WrapAuth(left, auth), nil
				}
				return left, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, _ := client.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
				if conn != nil {
					conn.Close()
				}
			}()
			header := make([]byte, 34)
			if _, err = io.ReadFull(right, header); err != nil {
				t.Fatal(err)
			}
			expected := sha256.Sum256([]byte(password))
			if private {
				expected = auth
			}
			if !bytes.Equal(header[:32], expected[:]) {
				t.Fatalf("auth %x", header[:32])
			}
			size := binary.BigEndian.Uint16(header[32:])
			padding := make([]byte, size)
			if _, err = io.ReadFull(right, padding); err != nil {
				t.Fatal(err)
			}
			if size != 30 || !bytes.Equal(padding, make([]byte, 30)) {
				t.Fatal("padding changed", size)
			}
			right.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("dial leaked")
			}
		})
	}
}
