// Package x365http 实现 X365 协议的承载层：REALITY/TLS 之上的
// HTTP/1.1 POST + Transfer-Encoding: chunked 流。
//
// 与官方新实现（mihomo 2026-10 build 718223992b53，adapter/outbound.prepareX365XHTTPHeaders
// + (*Vless).streamConnContext 反汇编）逐项核对一致：
//
//	POST <path> HTTP/1.1
//	Host: <伪装域名>
//	Content-Type: application/grpc
//	Transfer-Encoding: chunked
//	User-Agent: <覆盖为完整 Chrome UA>
//
// 之后每个 Write 立即做成一个 chunk 发出（上层 X365 握手帧即第一个 chunk），
// 服务端响应体同样是 chunked：首块 'X365' + 1B 状态（0 = 成功），其后是裸载荷。
//
// 关键点（踩过的坑，来自参考实现实测）：
//   - 服务端 ALPN 恒为 http/1.1，别用 h2：XHTTP 的 h2 通道在这个部署上不通。
//   - 必须 Transfer-Encoding: chunked；用 Content-Length 会被当一次性请求。
//   - 每次 Write 立即成块，不能缓冲，否则数据滞留、隧道建好但 0 字节。
//   - User-Agent 必须覆盖为 chrome UA：新版 x365 分支会先 delete 再 set
//     `User-Agent`（streamConnContext 内 addHeader 路径，值长 0x6f=111 字节），
//     不是默认 Go UA。伪装度不够会被中间层识别。
//   - 语义上等价于 xhttp 的 mode=stream-one：单一 POST 长期复用，
//     不做 packet-up/stream-up 的多请求上行。
package x365http

import (
	std_bufio "bufio"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/mods/modoption"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

// userAgent 是 x365 分支强制覆盖的 User-Agent 值，取自新版实现的
// 内联字符串常量（长度 0x6f = 111 字节，与 mihomo build 718223992b53 一致）。
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

type Client struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
	path       string
	host       string
	headers    http.Header
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
	return &Client{
		dialer:     dialer,
		serverAddr: serverAddr,
		path:       path,
		host:       host,
		headers:    headers,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialNew(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) dialNew(ctx context.Context) (*Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	var request strings.Builder
	request.WriteString("POST ")
	request.WriteString(c.path)
	request.WriteString(" HTTP/1.1\r\n")
	request.WriteString("Host: ")
	request.WriteString(c.host)
	request.WriteString("\r\n")
	for key, values := range c.headers {
		for _, value := range values {
			request.WriteString(key)
			request.WriteString(": ")
			request.WriteString(value)
			request.WriteString("\r\n")
		}
	}
	request.WriteString("Content-Type: application/grpc\r\n")
	request.WriteString("Transfer-Encoding: chunked\r\n")
	// 新版 x365 分支强制覆盖 User-Agent 为完整 chrome UA（不是 Go 默认值，
	// 也不是简写的 Mozilla/5.0）。缺失会被识别为非浏览器流量。
	request.WriteString("User-Agent: ")
	request.WriteString(userAgent)
	request.WriteString("\r\n")
	request.WriteString("\r\n")
	if _, err = conn.Write([]byte(request.String())); err != nil {
		conn.Close()
		return nil, E.Cause(err, "write x365 request")
	}
	tunnel := &Conn{Conn: conn, reader: std_bufio.NewReaderSize(conn, 64*1024)}
	// 请求头已发出，响应头可以立即在后台预读——Dial 不等它。
	tunnel.startHeadPrefetch()
	return tunnel, nil
}

func (c *Client) Close() error {
	return nil
}

// Conn 是 X365 隧道连接：写入自动 chunk 编码，读取自动 chunk 解码。
type Conn struct {
	net.Conn
	reader    *std_bufio.Reader
	headRead  bool
	body      net.Conn
	closeOnce bool
	writeBuf  [1 << 16]byte

	// 响应头异步预读：Dial 返回后立刻在后台读 HTTP 响应头 + X365 状态头，
	// 让下次 Read 直接命中（上游 xhttp 的 WaitReadCloser 等价做法）。
	headErr   error
	headReady chan struct{}
	headOnce  sync.Once
}

// startHeadPrefetch 在后台预读响应头，Dial 路径不再同步等 RTT。
func (c *Conn) startHeadPrefetch() {
	c.headReady = make(chan struct{})
	go func() {
		c.headErr = c.readHead()
		c.headOnce.Do(func() { close(c.headReady) })
	}()
}

func (c *Conn) readHead() error {
	if c.headRead {
		return nil
	}
	response, err := http.ReadResponse(c.reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		return E.Cause(err, "read x365 response head")
	}
	if response.StatusCode != http.StatusOK {
		var head strings.Builder
		response.Header.Write(&head) //nolint:errcheck
		detail := strings.Join(strings.Fields(head.String()), " ")
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return E.New("x365: unexpected status: ", response.Status, " headers=", detail)
	}
	c.headRead = true
	// http.Response.Body 已经内置 chunked 解码（含 trailer）。
	c.body = &bodyConn{Conn: c.Conn, reader: response.Body}
	return nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if !c.headRead {
		if c.headReady != nil {
			// 等后台预读完成，避免重复读同一段字节流。
			<-c.headReady
			if c.headErr != nil {
				return 0, c.headErr
			}
		} else if err := c.readHead(); err != nil {
			return 0, err
		}
	}
	return c.body.Read(p)
}

// Write 立即把数据做成一个 HTTP/1.1 chunk（不缓冲，见包注释）。
// 头部+载荷+CRLF 合并为一次 Write，避免每块 3 次 syscall 带来的小包延迟。
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var buf []byte
	// 大包直接分片写，避免额外一次拷贝。
	if len(p) < 1<<16 {
		buf = c.writeBuf[:0]
		buf = append(buf, strconv.FormatInt(int64(len(p)), 16)...)
		buf = append(buf, '\r', '\n')
		buf = append(buf, p...)
		buf = append(buf, '\r', '\n')
		if _, err := c.Conn.Write(buf); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if _, err := c.Conn.Write([]byte(strconv.FormatInt(int64(len(p)), 16) + "\r\n")); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(p); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write([]byte("\r\n")); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Close() error {
	if !c.closeOnce {
		c.closeOnce = true
		// 结束 chunked 请求体：0\r\n\r\n
		_, _ = c.Conn.Write([]byte("0\r\n\r\n"))
	}
	return c.Conn.Close()
}

// bodyConn 只借用底层 Conn 的生命周期，读写走响应体。
type bodyConn struct {
	net.Conn
	reader interface {
		Read([]byte) (int, error)
		Close() error
	}
}

func (b *bodyConn) Read(p []byte) (int, error) { return b.reader.Read(p) }
