package oppa

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	MC "github.com/sagernet/sing-box/mods/modconst"

	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestPreConnectPool verifies that a pool with pre_connect > 0 actually keeps
// warm connections and that the next dial reuses one instead of paying the TCP
// and TLS handshake again.
func TestPreConnectPool(t *testing.T) {
	certificate := selfSignedCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				// Minimal TLS server: handshake, then echo whatever arrives.
				tlsConn := tlsServerSide(conn, certificate)
				if tlsConn == nil {
					return
				}
				buffer := make([]byte, 256)
				for {
					n, readErr := tlsConn.Read(buffer)
					if n > 0 {
						_, _ = tlsConn.Write(buffer[:n])
					}
					if readErr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	instance, err := NewOutbound(context.Background(), nil, logger.NOP(), "pool-test", modoption.OppaOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(address.Port)},
		Password:      testPassword,
		PreConnect:    2,
	})
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	defer instance.(*Outbound).Close()
	outboundInstance := instance.(*Outbound)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := outboundInstance.DialContext(ctx, N.NetworkTCP, M.Socksaddr{Fqdn: "example.com", Port: 80})
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close()
	afterFirst := accepted.Load()
	if afterFirst != 1 {
		t.Fatalf("first dial opened %d connections, want 1", afterFirst)
	}
	// Wait for the deferred refill (poolFillDelay + dial time).
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if accepted.Load() >= 3 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	warmed := accepted.Load()
	if warmed < 3 {
		t.Fatalf("pool did not refill: %d connections accepted, want 3", warmed)
	}
	if idle := idleCount.Load(); idle <= 0 {
		t.Fatalf("idle count %d, want > 0", idle)
	}
	conn, err = outboundInstance.DialContext(ctx, N.NetworkTCP, M.Socksaddr{Fqdn: "example.com", Port: 80})
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	_, _ = conn.Write([]byte("ping"))
	conn.Close()
	if got := accepted.Load(); got != warmed {
		t.Fatalf("second dial opened %d connections, want reuse of a warm one (%d)", got, warmed)
	}
	_ = MC.TypeOppa
}
