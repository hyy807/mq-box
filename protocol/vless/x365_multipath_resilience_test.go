package vless

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type nopConn struct{}

func (nopConn) Read(b []byte) (int, error)       { return 0, io.EOF }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

type countedPath struct {
	dials atomic.Int32
	dial  func(context.Context) (net.Conn, error)
}

func (p *countedPath) DialContext(ctx context.Context) (net.Conn, error) {
	p.dials.Add(1)
	return p.dial(ctx)
}
func (p *countedPath) Close() error { return nil }

// An endpoint that failed must not be dialled again inside the cooldown window:
// the vendor kernel marks failed subflows for exactly this reason.
func TestX365MultipathSuppressesFailedEndpoint(t *testing.T) {
	failing := &countedPath{dial: func(context.Context) (net.Conn, error) {
		return nil, errors.New("reality rejected")
	}}
	healthy := &countedPath{dial: func(context.Context) (net.Conn, error) {
		// A real failure has to be observed while the parent context is still
		// alive, so the winner arrives a little later than the failing dial.
		time.Sleep(50 * time.Millisecond)
		return nopConn{}, nil
	}}
	transport := &x365MultipathTransport{
		paths:    []adapter.V2RayClientTransport{failing, healthy},
		cooldown: time.Minute,
	}
	for i := range 3 {
		conn, err := transport.DialContext(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.Close()
	}
	// The losing goroutine may be scheduled after the winner returned, so wait
	// for its first (and only) dial instead of assuming it already ran.
	deadline := time.Now().Add(2 * time.Second)
	for failing.dials.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := failing.dials.Load(); got != 1 {
		t.Fatalf("failed endpoint dialled %d times, want exactly 1 (then suppressed)", got)
	}
	for i := range 3 {
		conn, err := transport.DialContext(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.Close()
	}
	if got := failing.dials.Load(); got != 1 {
		t.Fatalf("suppressed endpoint was dialled %d times, want 1", got)
	}
	if got := healthy.dials.Load(); got < 3 {
		t.Fatalf("healthy endpoint dials = %d, want at least 3", got)
	}
}

// A stale failure table must never black the transport out: when every endpoint
// is suppressed, all of them become eligible again.
func TestX365MultipathClearsSuppressionWhenEverythingFails(t *testing.T) {
	first := &countedPath{dial: func(context.Context) (net.Conn, error) { return nil, errors.New("down") }}
	second := &countedPath{dial: func(context.Context) (net.Conn, error) { return nil, errors.New("down") }}
	transport := &x365MultipathTransport{
		paths:    []adapter.V2RayClientTransport{first, second},
		cooldown: time.Minute,
	}
	for i := range 2 {
		if _, err := transport.DialContext(context.Background()); err == nil {
			t.Fatalf("dial %d: expected all endpoints to fail", i)
		}
	}
	if first.dials.Load() != 2 || second.dials.Load() != 2 {
		t.Fatalf("all-failed transport must retry every endpoint, got %d and %d dials",
			first.dials.Load(), second.dials.Load())
	}
}

// The per-endpoint budget bounds the dial only. A winning connection keeps its
// context and must still carry data long after the budget elapsed.
func TestX365MultipathBudgetDoesNotCutTheWinner(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	winner := &countedPath{dial: func(context.Context) (net.Conn, error) { return left, nil }}
	transport := &x365MultipathTransport{
		paths:           []adapter.V2RayClientTransport{winner},
		endpointTimeout: 80 * time.Millisecond,
	}
	conn, err := transport.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(300 * time.Millisecond)
	// net.Pipe is synchronous: the write only completes once the reader reads.
	go func() { _, _ = right.Write([]byte("ok")) }()
	buffer := make([]byte, 2)
	if _, err = conn.Read(buffer); err != nil || string(buffer) != "ok" {
		t.Fatalf("winner was cut by the endpoint budget: %q %v", buffer, err)
	}
}

// A silently dropped endpoint must not hold the race open until the caller's
// deadline: the endpoint budget ends it on its own.
func TestX365MultipathBudgetBoundsHungEndpoint(t *testing.T) {
	hung := &countedPath{dial: func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	transport := &x365MultipathTransport{
		paths:           []adapter.V2RayClientTransport{hung},
		endpointTimeout: 120 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := transport.DialContext(ctx); err == nil {
		t.Fatal("expected the endpoint budget to fail the dial")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("endpoint budget did not bound the dial: %v", elapsed)
	}
}
