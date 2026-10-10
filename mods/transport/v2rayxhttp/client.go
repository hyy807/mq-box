// Package v2rayxhttp implements XHTTP client framing over HTTP/2. REALITY
// connections use stream-one; ordinary TLS uses packet-up in auto mode.
package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/mods/modoption"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	streamTransport *http2.Transport
	transport       *http2.Transport
	base            url.URL
	host            string
	headers         http.Header
	mode            string
	ctx             context.Context
	cancel          context.CancelFunc
}

func alpnError(negotiated string, offered []string) error {
	return fmt.Errorf("xhttp: TLS did not negotiate h2: negotiated=%q, offered=%q", negotiated, offered)
}

// alpnConfig is the subset of the TLS configuration the ALPN normalisation needs.
type alpnConfig interface {
	NextProtos() []string
	SetNextProtos([]string)
}

// normalizeALPN keeps the ALPN list the profile asks for and only requires that
// h2 is offered. The deployment under test answers an h2-only ClientHello with
// a no_application_protocol alert and completes the handshake again as soon as
// http/1.1 is offered next to h2, which is also what Chrome itself offers.
// Forcing h2-only here made every XHTTP/REALITY outbound fail against that
// server even though the profile advertised h2 + http/1.1. The protocol that
// was actually negotiated is still enforced on the wire below.
func normalizeALPN(config alpnConfig) error {
	offered := config.NextProtos()
	if len(offered) == 0 || (len(offered) == 1 && offered[0] == http2.NextProtoTLS) {
		offered = []string{http2.NextProtoTLS, "http/1.1"}
	}
	if !slices.Contains(offered, http2.NextProtoTLS) {
		// Never hand a []string to sing's exception formatter: it panics and
		// takes the iOS VPN extension down with it (see alpn_error_test.go).
		return fmt.Errorf("xhttp: h2 is missing from the offered ALPN list %q", offered)
	}
	config.SetNextProtos(offered)
	return nil
}

func normalizeXHTTPPath(u *url.URL) {
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	// XHTTP's default path placements normalize /name to /name/ even for
	// stream-one. The server matches that prefix before dispatching a stream.
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
		u.RawPath = ""
	}
}

func NewClient(dialer N.Dialer, server M.Socksaddr, opts modoption.XHTTPOptions, config tls.Config) (*Client, error) {
	if config == nil {
		return nil, E.New("xhttp requires TLS with h2")
	}
	config = config.Clone()
	if err := normalizeALPN(config); err != nil {
		return nil, err
	}
	mode := opts.Mode
	if mode == "" || mode == "auto" {
		if reality, ok := config.(interface{ IsReality() bool }); ok && reality.IsReality() {
			mode = "stream-one"
		} else {
			mode = "packet-up"
		}
	}
	if mode != "stream-one" && mode != "packet-up" {
		return nil, E.New("unsupported xhttp mode: ", mode)
	}
	u := url.URL{Scheme: "https", Host: server.String()}
	path := opts.Path
	if path == "" {
		path = "/"
	}
	if err := badhttp.URLSetPath(&u, path); err != nil {
		return nil, E.Cause(err, "parse xhttp path")
	}
	normalizeXHTTPPath(&u)
	if u.RawQuery != "" {
		return nil, E.New("xhttp path must not contain a query")
	}
	host := opts.Host
	headers := opts.Headers.Build()
	if host == "" {
		host = headers.Get("Host")
	}
	headers.Del("Host")
	if host == "" {
		host = config.ServerName()
	}
	if host == "" {
		host = server.AddrString()
	}
	ctx, cancel := context.WithCancel(context.Background())
	tlsDialer := tls.NewDialer(dialer, config)
	t, err := newBoundedTransport()
	if err != nil {
		cancel()
		return nil, err
	}
	t.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.STDConfig) (net.Conn, error) {
		conn, err := tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
		if err != nil {
			return nil, err
		}
		negotiated := conn.ConnectionState().NegotiatedProtocol
		// REALITY may authenticate successfully without advertising an ALPN
		// selection. mihomo's XHTTP h2 transport speaks HTTP/2 directly over
		// this TLS connection. Permit only that empty selection and let the
		// HTTP/2 preface/response validate the actual protocol on the wire.
		// An explicit HTTP/1.1 (or other) selection is never treated as h2.
		if negotiated != "" && negotiated != http2.NextProtoTLS {
			conn.Close()
			return nil, alpnError(negotiated, config.NextProtos())
		}
		return conn, nil
	}
	var streamTransport *http2.Transport
	if mode == "stream-one" {
		streamTransport, err = newBoundedTransport()
		if err != nil {
			cancel()
			return nil, err
		}
		streamTransport.DialTLSContext = t.DialTLSContext
	}
	return &Client{streamTransport: streamTransport, transport: t, base: u, host: host, headers: headers, mode: mode, ctx: ctx, cancel: cancel}, nil
}

// Close drops the pooled HTTP/2 connections but keeps the client usable.
//
// sing-box closes an outbound transport on every network change
// (adapter.InterfaceUpdateListener.InterfaceUpdated -> ResetNetwork) and then
// keeps dialing through the same client: the HTTP, WebSocket and HTTPUpgrade
// clients all stay usable after Close, and v2rayhttp replaces its round
// tripper instead of disabling it. Cancelling a client-wide context here made
// every later DialContext return net.ErrClosed, which killed the outbound
// permanently until the tunnel was restarted by hand.
func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	if c.streamTransport != nil {
		c.streamTransport.CloseIdleConnections()
	}
	return nil
}

const xhttpReceiveWindow = 256 << 10

func newBoundedTransport() (*http2.Transport, error) {
	h1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerStream:     xhttpReceiveWindow,
		MaxReceiveBufferPerConnection: xhttpReceiveWindow,
	}, MaxResponseHeaderBytes: 32 << 10}
	t, err := http2.ConfigureTransports(h1)
	if err != nil {
		return nil, err
	}
	// ConfigureTransports installs an HTTP/1-owned no-dial pool. XHTTP calls
	// RoundTrip directly, so use http2's native dialing pool instead.
	t.ConnPool = nil
	return t, nil
}

func (c *Client) sessionTransport() (*http2.Transport, error) {
	if c.mode == "stream-one" {
		return c.streamTransport, nil
	}
	return c.transport, nil
}

func (c *Client) request(ctx context.Context, method string, u url.URL, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = c.host
	req.Header = c.headers.Clone()
	// Xray XHTTP default framing: padding in Referer and gRPC content type on streams.
	referer := u
	referer.RawQuery = "x_padding=" + strings.Repeat("X", 128)
	req.Header.Set("Referer", referer.String())
	if body != nil && method == http.MethodPost {
		req.Header.Set("Content-Type", "application/grpc")
	}
	return req, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.ctx.Err(); err != nil {
		return nil, net.ErrClosed
	}
	sessionCtx, cancel := context.WithCancel(c.ctx)
	transport, err := c.sessionTransport()
	if err != nil {
		cancel()
		return nil, err
	}
	// The dial context only governs establishing the connection, not its lifetime.
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	u := c.base
	var body io.Reader
	var writer io.WriteCloser
	var session string
	if c.mode == "stream-one" {
		r, w := io.Pipe()
		body, writer = r, w
	} else {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			cancel()
			return nil, err
		}
		session = hex.EncodeToString(id[:])
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + session
	}
	connected := make(chan struct{}, 1)
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
		select {
		case connected <- struct{}{}:
		default:
		}
	}}
	reqCtx := httptrace.WithClientTrace(sessionCtx, trace)
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := c.request(reqCtx, method, u, body)
	if err != nil {
		cancel()
		if writer != nil {
			writer.Close()
		}
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/grpc")
	}
	ready := make(chan result)
	go func() {
		resp, err := transport.RoundTrip(req)
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("xhttp: unexpected status %s", resp.Status)
			resp.Body.Close()
		}
		r := result{err: err}
		if err == nil {
			r.body = resp.Body
		}
		select {
		case ready <- r:
		case <-sessionCtx.Done():
			// The connection was closed before this result could be consumed, so
			// nobody will ever drain the channel. Release the response body here
			// instead of parking a goroutine to collect it later.
			if r.body != nil {
				r.body.Close()
			}
		}
	}()
	var initial result
	select {
	case <-connected:
	case initial = <-ready:
		if initial.err != nil {
			cancel()
			if writer != nil {
				writer.Close()
			}
			return nil, initial.err
		}
	case <-ctx.Done():
		cancel()
		if writer != nil {
			writer.Close()
		}
		return nil, ctx.Err()
	}
	conn := &connection{reader: ready, writer: writer, cancel: cancel, done: make(chan struct{}), initial: initial}
	if session != "" {
		conn.writer = &packetWriter{client: c, ctx: sessionCtx, base: u}
	}
	return conn, nil
}

type result struct {
	body io.ReadCloser
	err  error
}
type connection struct {
	reader    chan result
	initial   result
	once      sync.Once
	bodyMu    sync.Mutex
	body      io.ReadCloser
	writer    io.WriteCloser
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

func (c *connection) Read(p []byte) (int, error) {
	c.once.Do(func() {
		r := c.initial
		if r.body == nil && r.err == nil {
			select {
			case r = <-c.reader:
			case <-c.done:
				r.err = net.ErrClosed
			}
		}
		c.bodyMu.Lock()
		select {
		case <-c.done:
			if r.body != nil {
				r.body.Close()
			}
			r.err = net.ErrClosed
		default:
		}
		c.body = r.body
		c.bodyMu.Unlock()
		c.initial.err = r.err
	})
	if c.initial.err != nil {
		return 0, c.initial.err
	}
	n, err := c.body.Read(p)
	if err != nil {
		select {
		case <-c.done:
			return n, net.ErrClosed
		default:
		}
	}
	return n, err
}
func (c *connection) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	return c.writer.Write(p)
}
func (c *connection) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		// Cancelling the session context aborts an in-flight RoundTrip and makes
		// the request goroutine release its own response body, so no waiter is
		// needed here. Parking a goroutine per closed connection for up to a
		// minute is what exhausted the extension: the profile showed 614 of 878
		// goroutines sitting in connection.Close while memory climbed past the
		// 50 MB limit.
		c.cancel()
		if c.writer != nil {
			c.writer.Close()
		}
		c.bodyMu.Lock()
		if c.body != nil {
			c.body.Close()
		}
		c.bodyMu.Unlock()
	})
	return nil
}
func (*connection) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (*connection) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (*connection) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (*connection) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (*connection) SetWriteDeadline(time.Time) error { return os.ErrInvalid }
func (*connection) NeedAdditionalReadDeadline() bool { return true }

// packetWriter sends ordered, bounded POSTs to /path/session/sequence.
// Unlike stream-one each POST is independently acknowledged by the server.
type packetWriter struct {
	client *Client
	ctx    context.Context
	base   url.URL
	mu     sync.Mutex
	seq    uint64
	closed bool
}

func (w *packetWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 1000000 {
			n = 1000000
		}
		u := w.base
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strconv.FormatUint(w.seq, 10)
		w.seq++
		req, err := w.client.request(w.ctx, http.MethodPost, u, bytes.NewReader(p[:n]))
		if err != nil {
			return total, err
		}
		req.Header.Del("Content-Type")
		resp, err := w.client.transport.RoundTrip(req)
		if err != nil {
			return total, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return total, fmt.Errorf("xhttp packet-up: unexpected status %s", resp.Status)
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (w *packetWriter) Close() error { w.mu.Lock(); defer w.mu.Unlock(); w.closed = true; return nil }
