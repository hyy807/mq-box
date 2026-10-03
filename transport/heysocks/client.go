// Package heysocks HTTP/2 carrier: TLS with the Chrome fingerprint, ALPN h2,
// then one long-lived POST whose request body is the encrypted upstream stream
// and whose response body is the downstream stream.
package heysocks

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

type Client struct {
	dialer    N.Dialer
	server    M.Socksaddr
	tlsConfig tls.Config
	transport *http2.Transport
	base      url.URL
	host      string
	headers   http.Header
	debug     func(format string, args ...any)
}

const receiveWindow = 256 << 10

func NewClient(dialer N.Dialer, server M.Socksaddr, tlsConfig tls.Config, host string, path string, headers http.Header, debug func(format string, args ...any)) (*Client, error) {
	if tlsConfig == nil {
		return nil, E.New("heysocks: TLS is required")
	}
	tlsConfig = tlsConfig.Clone()
	// The reference transport only speaks HTTP/2; advertising http/1.1 would
	// let the server select a protocol this client cannot speak.
	if strict, ok := tlsConfig.(interface{ SetNextProtosOnly([]string) }); ok {
		strict.SetNextProtosOnly([]string{http2.NextProtoTLS})
	} else {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
	}
	// A Chrome fingerprint keeps http/1.1 next to h2 in the ClientHello, which
	// is what Chrome itself offers; h2 must be among them and the negotiated
	// protocol is enforced below.
	offered := tlsConfig.NextProtos()
	if !slices.Contains(offered, http2.NextProtoTLS) {
		return nil, E.New("heysocks: h2 is missing from the offered ALPN list ", offered)
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if host == "" {
		host = tlsConfig.ServerName()
	}
	if host == "" {
		host = server.AddrString()
	}
	h1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerStream:     receiveWindow,
		MaxReceiveBufferPerConnection: receiveWindow,
	}, MaxResponseHeaderBytes: 32 << 10}
	transport, err := http2.ConfigureTransports(h1)
	if err != nil {
		return nil, E.Cause(err, "heysocks: configure HTTP/2 transport")
	}
	transport.ConnPool = nil
	tlsDialer := tls.NewDialer(dialer, tlsConfig)
	transport.DialTLSContext = func(ctx context.Context, network string, addr string, _ *tls.STDConfig) (net.Conn, error) {
		conn, dialErr := tlsDialer.DialTLSContext(ctx, server)
		if dialErr != nil {
			return nil, dialErr
		}
		state := conn.ConnectionState()
		negotiated := state.NegotiatedProtocol
		if debug != nil {
			debug("carrier tls: version=%x cipher=%x alpn=%q sni=%q peer_certs=%d",
				state.Version, state.CipherSuite, negotiated, state.ServerName, len(state.PeerCertificates))
		}
		if negotiated != http2.NextProtoTLS {
			conn.Close()
			return nil, E.New("heysocks: TLS did not negotiate h2: negotiated=", negotiated)
		}
		return conn, nil
	}
	return &Client{
		dialer:    dialer,
		server:    server,
		tlsConfig: tlsConfig,
		transport: transport,
		debug:     debug,
		base:      url.URL{Scheme: "https", Host: server.String(), Path: path},
		host:      host,
		headers:   headers,
	}, nil
}

func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

// DialContext opens one carrier stream. The caller writes the framed upstream
// bytes into the returned connection.
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	pipeReader, pipeWriter := io.Pipe()
	request, err := http.NewRequestWithContext(sessionCtx, http.MethodPost, c.base.String(), pipeReader)
	if err != nil {
		cancel()
		stop()
		return nil, err
	}
	request.Host = c.host
	if len(c.headers) > 0 {
		request.Header = c.headers.Clone()
	}
	if request.Header == nil {
		request.Header = make(http.Header, 2)
	}
	// The carrier is the v2ray XHTTP shape (spec section 2): the reference
	// clients label the stream request application/grpc.
	request.Header.Set("Content-Type", "application/grpc")
	connected := make(chan struct{}, 1)
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
		select {
		case connected <- struct{}{}:
		default:
		}
	}}
	request = request.WithContext(httptrace.WithClientTrace(sessionCtx, trace))

	if c.debug != nil {
		c.debug("carrier out: POST host=%s path=%s headers=%d", c.host, c.base.Path, len(c.headers))
	}
	conn := &streamConn{
		client:     c,
		pipeReader: pipeReader,
		pipeWriter: pipeWriter,
		ready:      make(chan struct{}),
		cancel:     cancel,
		stop:       stop,
	}
	go func() {
		response, roundErr := c.transport.RoundTrip(request)
		if c.debug != nil {
			if response != nil {
				c.debug("carrier result: status=%s err=%v", response.Status, roundErr)
			} else {
				c.debug("carrier result: no response err=%v", roundErr)
			}
		}
		if roundErr == nil && response.StatusCode != http.StatusOK {
			roundErr = E.New("heysocks: unexpected status ", response.Status)
			response.Body.Close()
			response = nil
		}
		conn.setResult(response, roundErr)
	}()
	select {
	case <-connected:
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
	return conn, nil
}

type streamConn struct {
	client     *Client
	dumpedRead bool
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	ready      chan struct{}
	readyOnce  sync.Once
	bodyMu     sync.Mutex
	body       io.ReadCloser
	err        error
	cancel     context.CancelFunc
	stop       func() bool
	closeOnce  sync.Once
}

func (c *streamConn) setResult(response *http.Response, err error) {
	c.bodyMu.Lock()
	if response != nil {
		c.body = response.Body
	}
	c.err = err
	c.bodyMu.Unlock()
	c.readyOnce.Do(func() { close(c.ready) })
}

func (c *streamConn) Read(p []byte) (int, error) {
	<-c.ready
	c.bodyMu.Lock()
	body := c.body
	err := c.err
	c.bodyMu.Unlock()
	if err != nil {
		return 0, err
	}
	if body == nil {
		return 0, io.EOF
	}
	n, readErr := body.Read(p)
	if !c.dumpedRead && n > 0 {
		c.dumpedRead = true
		if c.client != nil && c.client.debug != nil {
			c.client.debug("carrier in: first %d bytes: %s", n, hexPreview(p[:n], 128))
		}
	}
	return n, readErr
}

func (c *streamConn) Write(p []byte) (int, error) {
	return c.pipeWriter.Write(p)
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		if c.stop != nil {
			c.stop()
		}
		_ = c.pipeWriter.Close()
		_ = c.pipeReader.Close()
		c.bodyMu.Lock()
		if c.body != nil {
			_ = c.body.Close()
		}
		c.bodyMu.Unlock()
		c.readyOnce.Do(func() { close(c.ready) })
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (c *streamConn) RemoteAddr() net.Addr               { return M.Socksaddr{} }
func (c *streamConn) SetDeadline(time.Time) error        { return os.ErrInvalid }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }

func (c *streamConn) NeedAdditionalReadDeadline() bool { return true }
