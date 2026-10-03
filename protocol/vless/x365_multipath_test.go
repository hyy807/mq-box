package vless

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type testPath struct {
	dial   func(context.Context) (net.Conn, error)
	resets atomic.Int32
}

func (p *testPath) DialContext(ctx context.Context) (net.Conn, error) { return p.dial(ctx) }
func (p *testPath) Close() error                                      { p.resets.Add(1); return nil }

type trackedConn struct {
	net.Conn
	closed chan struct{}
	once   atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.once.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return c.Conn.Close()
}

func TestX365MultipathParallelFirstSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := make(chan int, 7)
	release := make(chan struct{})
	losers := make(chan int, 6)
	left, right := net.Pipe()
	defer right.Close()
	var winnerCtx context.Context
	paths := make([]adapter.V2RayClientTransport, 7)
	for i := range paths {
		paths[i] = &testPath{dial: func(ctx context.Context) (net.Conn, error) {
			started <- i
			if i == 3 {
				winnerCtx = ctx
				select {
				case <-release:
					return left, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			<-ctx.Done()
			losers <- i
			return nil, ctx.Err()
		}}
	}
	tr := &x365MultipathTransport{paths: paths}
	result := make(chan net.Conn, 1)
	go func() {
		c, e := tr.DialContext(ctx)
		if e != nil {
			t.Error(e)
		}
		result <- c
	}()
	for range paths {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("not all seven paths launched")
		}
	}
	close(release)
	var conn net.Conn
	select {
	case conn = <-result:
	case <-ctx.Done():
		t.Fatal("winner did not return")
	}
	if conn == nil {
		t.Fatal("nil winner")
	}
	defer conn.Close()
	for range 6 {
		select {
		case <-losers:
		case <-ctx.Done():
			t.Fatal("loser not cancelled")
		}
	}
	if winnerCtx.Err() != nil {
		t.Fatal("winner was cancelled")
	}
	go right.Write([]byte("ok"))
	b := make([]byte, 2)
	if _, e := conn.Read(b); e != nil || string(b) != "ok" {
		t.Fatalf("winner unusable: %q %v", b, e)
	}
	conn.Close()
	select {
	case <-winnerCtx.Done():
	case <-ctx.Done():
		t.Fatal("winner close did not cancel context")
	}
}

func TestX365MultipathLateSuccessClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	c, d := net.Pipe()
	defer d.Close()
	late := &trackedConn{Conn: c, closed: make(chan struct{})}
	unblock := make(chan struct{})
	tr := &x365MultipathTransport{paths: []adapter.V2RayClientTransport{
		&testPath{dial: func(context.Context) (net.Conn, error) { return a, nil }},
		&testPath{dial: func(context.Context) (net.Conn, error) { <-unblock; return late, nil }},
	}}
	conn, e := tr.DialContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	close(unblock)
	select {
	case <-late.closed:
	case <-ctx.Done():
		t.Fatal("late successful loser leaked")
	}
}

func TestX365MultipathFailureCancellationAndReset(t *testing.T) {
	failure := errors.New("reality rejected")
	bad := &testPath{dial: func(context.Context) (net.Conn, error) { return nil, failure }}
	tr := &x365MultipathTransport{paths: []adapter.V2RayClientTransport{bad, bad}}
	for range 2 {
		if _, e := tr.DialContext(context.Background()); !errors.Is(e, failure) {
			t.Fatalf("missing failure: %v", e)
		}
		if e := tr.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if bad.resets.Load() != 4 {
		t.Fatal("reset did not reach every child")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := tr.DialContext(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	blocked := &testPath{dial: func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	if _, e := (&x365MultipathTransport{paths: []adapter.V2RayClientTransport{blocked}}).DialContext(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
