package vless

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// defaultMultipathEndpointTimeout bounds one endpoint's dial. Without it a
	// silently dropped endpoint keeps the race open until the caller's context
	// expires, which the user sees as "no latency at all".
	defaultMultipathEndpointTimeout = 8 * time.Second
	// defaultMultipathCooldown suppresses an endpoint after it failed, mirroring
	// the vendor kernel's "mark failed subflows to suppress retries". The table
	// is cleared whenever every endpoint is suppressed, so the transport can
	// never black itself out.
	defaultMultipathCooldown = 2 * time.Minute
)

// The endpoint list is authoritative: server/server_port are ignored when it
// is present. Each child constructs its own REALITY config and XHTTP pool.
func newX365MultipathOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSOutboundOptions) (adapter.Outbound, error) {
	if !options.X365 && !strings.HasSuffix(options.UUID, "#x365") {
		return nil, E.New("x365_multipath requires x365")
	}
	if options.Transport == nil || options.Transport.Type != "xhttp" || options.TLS == nil || !options.TLS.Enabled || options.TLS.Reality == nil || !options.TLS.Reality.Enabled {
		return nil, E.New("x365_multipath requires XHTTP with REALITY")
	}
	if options.Transport.XHTTPOptions.Mode != "" && options.Transport.XHTTPOptions.Mode != "auto" && options.Transport.XHTTPOptions.Mode != "stream-one" {
		return nil, E.New("x365_multipath requires stream-one mode")
	}
	if options.Multiplex != nil && options.Multiplex.Enabled {
		return nil, E.New("x365_multipath does not support outbound multiplex")
	}
	paths := &x365MultipathTransport{}
	var first *Outbound
	seen := make(map[string]bool)
	for _, endpoint := range options.X365Multipath {
		if endpoint.Server == "" || endpoint.ServerPort == 0 {
			paths.Close()
			return nil, E.New("x365_multipath endpoint requires server and server_port")
		}
		address := endpoint.Build().String()
		if seen[address] {
			paths.Close()
			return nil, E.New("duplicate x365_multipath endpoint: ", address)
		}
		seen[address] = true
		childOptions := options
		childOptions.X365Multipath = nil
		childOptions.ServerOptions = endpoint
		child, err := NewOutbound(ctx, router, logger, tag, childOptions)
		if err != nil {
			paths.Close()
			return nil, E.Cause(err, "create x365 multipath endpoint: ", address)
		}
		outbound := child.(*Outbound)
		if first == nil {
			first = outbound
		}
		paths.paths = append(paths.paths, outbound.transport)
	}
	first.transport = paths
	return first, nil
}

// Race complete carrier dials, not raw TCP sockets: a reachable endpoint whose
// REALITY handshake fails must never win. XHTTP DialContext succeeds at GotConn
// (authenticated TLS/H2 carrier), before the lazy X365 request is written.
// No application payload is duplicated. This is racing, not stream striping.
type x365MultipathTransport struct {
	paths []adapter.V2RayClientTransport

	// endpointTimeout and cooldown default to the constants above; tests set
	// them to short values. They are not configuration keys.
	endpointTimeout time.Duration
	cooldown        time.Duration

	mu       sync.Mutex
	failedAt map[int]time.Time
}

func (t *x365MultipathTransport) budget() time.Duration {
	if t.endpointTimeout > 0 {
		return t.endpointTimeout
	}
	return defaultMultipathEndpointTimeout
}

func (t *x365MultipathTransport) cooldownWindow() time.Duration {
	if t.cooldown > 0 {
		return t.cooldown
	}
	return defaultMultipathCooldown
}

// candidates returns the endpoints worth dialling right now. Endpoints that
// failed inside the cooldown window are skipped; when that would leave nothing
// to try the table is cleared and every endpoint is eligible again (a stale
// failure must never turn into a permanent blackout).
func (t *x365MultipathTransport) candidates(now time.Time) []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	window := t.cooldownWindow()
	list := make([]int, 0, len(t.paths))
	for i := range t.paths {
		if failed, ok := t.failedAt[i]; ok && now.Sub(failed) < window {
			continue
		}
		list = append(list, i)
	}
	if len(list) == 0 {
		t.failedAt = nil
		for i := range t.paths {
			list = append(list, i)
		}
	}
	return list
}

func (t *x365MultipathTransport) markFailure(index int, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failedAt == nil {
		t.failedAt = make(map[int]time.Time)
	}
	t.failedAt[index] = now
}

func (t *x365MultipathTransport) markSuccess(index int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failedAt, index)
}

func (t *x365MultipathTransport) DialContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selected := t.candidates(time.Now())
	type result struct {
		conn  net.Conn
		err   error
		index int
	}
	results := make(chan result)
	done := make(chan struct{})
	defer close(done)
	cancels := make([]context.CancelFunc, len(t.paths))
	timers := make([]*time.Timer, len(t.paths))
	timedOut := make([]atomic.Bool, len(t.paths))
	winner := -1
	defer func() {
		for i := range t.paths {
			if i == winner {
				continue
			}
			if timers[i] != nil {
				timers[i].Stop()
			}
			if cancels[i] != nil {
				cancels[i]()
			}
		}
	}()
	budget := t.budget()
	for _, i := range selected {
		path := t.paths[i]
		childCtx, cancel := context.WithCancel(ctx)
		cancels[i] = cancel
		// The budget is enforced per endpoint, and it only bounds the dial. A
		// winning connection keeps its context: the timer is stopped before the
		// connection is handed out, so long-lived sessions are not cut at the
		// budget.
		timers[i] = time.AfterFunc(budget, func() {
			timedOut[i].Store(true)
			cancel()
		})
		go func(index int, path adapter.V2RayClientTransport, ctx context.Context) {
			conn, err := path.DialContext(ctx)
			if err != nil && conn != nil {
				conn.Close()
				conn = nil
			}
			if err != nil {
				// Record the failure here, not in the consumer: when a winner
				// returns first the losing goroutine is still in flight, and its
				// failure must suppress that endpoint on the next dial. An
				// endpoint that burned its whole budget counts as failed; one
				// that was merely cancelled because another endpoint won does
				// not.
				if ctx.Err() == nil || timedOut[index].Load() {
					t.markFailure(index, time.Now())
				}
			}
			select {
			case results <- result{conn, err, index}:
			case <-done:
				if conn != nil {
					conn.Close()
				}
			}
		}(i, path, childCtx)
	}
	var failures []error
	for range selected {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			if r.err != nil {
				failures = append(failures, r.err)
				continue
			}
			if err := ctx.Err(); err != nil {
				r.conn.Close()
				return nil, err
			}
			t.markSuccess(r.index)
			winner = r.index
			timers[winner].Stop()
			return &x365PathConn{Conn: r.conn, cancel: cancels[winner]}, nil
		}
	}
	return nil, E.Cause(errors.Join(failures...), "all x365 multipath endpoints failed")
}

func (t *x365MultipathTransport) Close() error {
	var failures []error
	for _, path := range t.paths {
		if err := path.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Keep reset reusable, matching XHTTP Close; never cancel a client-wide context.
func (t *x365MultipathTransport) SetKeepIdleConnections(keep bool) {
	for _, path := range t.paths {
		if keeper, ok := path.(adapter.IdleConnectionKeeper); ok {
			keeper.SetKeepIdleConnections(keep)
		}
	}
}
func (t *x365MultipathTransport) CloseIdleConnections() {
	for _, path := range t.paths {
		if keeper, ok := path.(adapter.IdleConnectionKeeper); ok {
			keeper.CloseIdleConnections()
		}
	}
}

type x365PathConn struct {
	net.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func (c *x365PathConn) Close() error {
	c.once.Do(c.cancel)
	return c.Conn.Close()
}
