// Package x365http 实现 X365 协议的承载层。
//
// 隧道层完全照上游官方 mihomo transport/xhttp 的 stream-one 设计
// （client.go: DialStreamOne / reuse.go: ReuseManager）：
//
//   - 底层 net.Conn（REALITY/TLS）由本包提供，塞进标准库 http.Transport
//     的 DialTLSContext；
//   - 由 http.Transport 自带的 keep-alive 连接池负责 TCP 复用；
//   - ReuseManager 管理多个 http.Transport 实例并按负载轮换；
//   - 请求体用 io.Pipe 流式发送，第一个 Write 即 X365 握手帧；
//   - 用 httptrace.GotConn 在 TCP 建好瞬间返回 conn，不等 HTTP 响应，
//     避免 CDN 缓冲响应头导致的死锁（上游注释原话）。
//
// 与上游的唯一差异是「协议兼容」部分：请求头按 X365 的伪装要求构造
// （POST + application/grpc + chunked + 完整 Chrome UA），响应体首块为
// 'X365' + 1B 状态码。
package x365http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/mods/modoption"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

// userAgent 是 x365 分支强制覆盖的 User-Agent 值（长度 0x6f = 111 字节，
// 与 mihomo build 718223992b53 内联常量一致）。缺失会被识别为非浏览器流量。
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// 连接池参数，取值对齐上游 xhttp 的默认量级。
const (
	defaultIdleConnTimeout = 90 * time.Second
	defaultMaxConcurrency  = 8
	defaultMaxConnections  = 4
)

// TransportMaker 新建一个底层 http.RoundTripper（含独立连接池）。
type TransportMaker func() http.RoundTripper

type Client struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
	path       string
	host       string
	headers    http.Header
	reuse      *ReuseManager
}

func NewClient(dialer N.Dialer, serverAddr M.Socksaddr, options modoption.X365Options, tlsConfig tls.Config) (*Client, error) {
	if tlsConfig != nil {
		// 服务端只讲 http/1.1；强制覆盖 ALPN，避免协商到 h2 后帧格式不符。
		tlsConfig.SetNextProtos([]string{"http/1.1"})
		dialer = tls.NewDialer(dialer, tlsConfig)
	}
	host := options.Host
	if host == "" && tlsConfig != nil {
		host = tlsConfig.ServerName()
	}
	if host == "" {
		host = serverAddr.AddrString()
	}
	path := options.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	headers := make(http.Header)
	for key, value := range options.Headers {
		headers[key] = value
	}
	client := &Client{
		dialer:     dialer,
		serverAddr: serverAddr,
		path:       path,
		host:       host,
		headers:    headers,
	}
	client.reuse = NewReuseManager(defaultMaxConnections, defaultMaxConcurrency, client.makeTransport)
	return client, nil
}

// makeTransport 照上游 xhttp 的做法：把本协议的底层 net.Conn 直接
// 作为 http.Transport 的 DialTLSContext，从而白拿标准库的 keep-alive 连接池。
func (c *Client) makeTransport() http.RoundTripper {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
		},
		IdleConnTimeout:     defaultIdleConnTimeout,
		ForceAttemptHTTP2:   false, // X365 只走 http/1.1
		DisableCompression:  true,
		MaxIdleConnsPerHost: defaultMaxConcurrency,
	}
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	transport := c.reuse.GetTransport()
	requestURL := url.URL{
		Scheme: "https",
		Host:   c.host,
		Path:   c.path,
	}
	pr, pw := io.Pipe()
	conn := &Conn{writer: pw}

	// GotConn 在 TCP 建好的一瞬触发，于是可以在不等 HTTP 响应的情况下
	// 返回 conn——这正是上游用来打破「CDN 缓冲响应头」死锁的手段。
	gotConn := make(chan bool, 1)
	streamCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			select {
			case gotConn <- true:
			default: // GotConn 可能被多次调用，忽略后续
			}
		},
	})

	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = transport.Close()
		return nil, E.Cause(err, "build x365 request")
	}
	req.Host = c.host
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("User-Agent", userAgent)
	for key, values := range c.headers {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}
	// 用 chunked，禁用标准库对长度的推断。
	req.ContentLength = -1

	wrc := newWaitReadCloser()

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			wrc.CloseWithError(err)
			select {
			case gotConn <- false:
			default:
			}
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			wrc.CloseWithError(E.New("x365 stream-one bad status: ", resp.Status))
			return
		}
		wrc.Set(&statusReader{status: resp.Body})
	}()

	if !<-gotConn {
		_ = pr.Close()
		_ = pw.Close()
		_ = transport.Close()
		var buf [1]byte
		_, err = wrc.Read(buf[:])
		if err == nil {
			err = E.New("x365: round trip failed before connect")
		}
		return nil, err
	}

	conn.reader = wrc
	conn.onClose = func() {
		_ = pr.Close()
		_ = transport.Close()
	}
	return conn, nil
}

// Close 释放本 Client 占用的所有连接池。
func (c *Client) Close() error {
	return c.reuse.Close()
}

// Conn 是 X365 隧道连接：写入即 chunk（由 io.Pipe 天然分帧），
// 读取走响应体（首 5 字节是 X365 状态头）。
type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
}

func (c *Conn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *Conn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *Conn) Close() error {
	var errs []error
	if c.writer != nil {
		errs = append(errs, c.writer.Close())
	}
	if c.reader != nil {
		errs = append(errs, c.reader.Close())
	}
	if c.onClose != nil {
		c.onClose()
	}
	return errors.Join(errs...)
}

// 隧道是长连接，deadline 由上层负责；这里不额外实现。
func (c *Conn) LocalAddr() net.Addr  { return dummyAddr{} }
func (c *Conn) RemoteAddr() net.Addr { return dummyAddr{} }
func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "x365" }
func (dummyAddr) String() string  { return "x365" }

// statusReader 校验响应体首 5 字节的 X365 状态头，其后透传。
type statusReader struct {
	status io.ReadCloser
	once   sync.Once
	err    error
	head   []byte
}

func (s *statusReader) Read(p []byte) (int, error) {
	s.once.Do(func() {
		var head [5]byte
		if _, err := io.ReadFull(s.status, head[:]); err != nil {
			s.err = E.Cause(err, "read x365 response status")
			return
		}
		if string(head[0:4]) != "X365" {
			s.err = E.New("x365: bad response magic: ", string(head[0:4]))
			return
		}
		if head[4] != 0 {
			s.err = E.New("x365: server rejected, status=", head[4])
		}
	})
	if s.err != nil {
		return 0, s.err
	}
	return s.status.Read(p)
}

func (s *statusReader) Close() error { return s.status.Close() }

// waitReadCloser 是上游 WaitReadCloser 的等价实现：Read 阻塞到 Set 被调用，
// 从而让 RoundTrip 可以在后台 goroutine 里进行。
type waitReadCloser struct {
	ready  chan struct{}
	source io.ReadCloser
	err    error
	once   sync.Once
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{ready: make(chan struct{})}
}

func (w *waitReadCloser) Set(rc io.ReadCloser) {
	w.source = rc
	w.once.Do(func() { close(w.ready) })
}

func (w *waitReadCloser) CloseWithError(err error) {
	w.err = err
	w.once.Do(func() { close(w.ready) })
}

func (w *waitReadCloser) Read(p []byte) (int, error) {
	<-w.ready
	if w.err != nil {
		return 0, w.err
	}
	if w.source == nil {
		return 0, io.EOF
	}
	return w.source.Read(p)
}

func (w *waitReadCloser) Close() error {
	w.once.Do(func() { close(w.ready) })
	if w.source != nil {
		return w.source.Close()
	}
	return nil
}

// ReuseManager 管理多个 http.RoundTripper 实例（各自带连接池），
// 按 openUsage 最低者挑选，语义对齐上游 xhttp 的 ReuseManager。
type ReuseManager struct {
	maxConnections int
	maxConcurrency int
	maker          TransportMaker
	mu             sync.Mutex
	entries        []*reuseEntry
}

type reuseEntry struct {
	transport   http.RoundTripper
	openUsage   atomic.Int32
	leftRequest atomic.Int32
	closed      atomic.Bool
}

func NewReuseManager(maxConnections, maxConcurrency int, maker TransportMaker) *ReuseManager {
	return &ReuseManager{
		maxConnections: maxConnections,
		maxConcurrency: maxConcurrency,
		maker:          maker,
	}
}

func (m *ReuseManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.entries {
		entry.close()
	}
	m.entries = nil
	return nil
}

func (entry *reuseEntry) close() {
	if !entry.closed.CompareAndSwap(false, true) {
		return
	}
	if closer, ok := entry.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (entry *reuseEntry) release() {
	remaining := entry.openUsage.Add(-1)
	if remaining <= 0 {
		entry.openUsage.Store(0)
	}
}

func (m *ReuseManager) GetTransport() *reuseTransport {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 清理已关闭的条目
	kept := m.entries[:0]
	for _, entry := range m.entries {
		if entry.closed.Load() {
			continue
		}
		kept = append(kept, entry)
	}
	m.entries = kept

	var entry *reuseEntry
	if len(m.entries) >= m.maxConnections {
		var best *reuseEntry
		for _, candidate := range m.entries {
			if m.maxConcurrency > 0 && int(candidate.openUsage.Load()) >= m.maxConcurrency {
				continue
			}
			if best == nil || candidate.openUsage.Load() < best.openUsage.Load() {
				best = candidate
			}
		}
		entry = best
	}
	if entry == nil {
		entry = &reuseEntry{transport: m.maker()}
		entry.leftRequest.Store(1<<30 - 1)
		m.entries = append(m.entries, entry)
	}
	entry.openUsage.Add(1)
	return &reuseTransport{entry: entry}
}

type reuseTransport struct {
	entry *reuseEntry
	once  sync.Once
}

func (rt *reuseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.entry.transport.RoundTrip(req)
}

func (rt *reuseTransport) Close() error {
	rt.once.Do(func() { rt.entry.release() })
	return nil
}
