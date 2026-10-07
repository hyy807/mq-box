// Package x365http 实现 X365 协议的承载层：REALITY/TLS 之上的
// HTTP/1.1 POST + Transfer-Encoding: chunked 流。
//
// 与官方参考实现（gox365）字节一致：
//
//	POST <path> HTTP/1.1
//	Host: <伪装域名>
//	Content-Type: application/grpc
//	Transfer-Encoding: chunked
//	User-Agent: Mozilla/5.0
//
// 之后每个 Write 立即做成一个 chunk 发出（上层 X365 握手帧即第一个 chunk），
// 服务端响应体同样是 chunked：首块 'X365' + 1B 状态（0 = 成功），其后是裸载荷。
//
// 关键点（踩过的坑，来自参考实现实测）：
//   - 服务端 ALPN 恒为 http/1.1，别用 h2：XHTTP 的 h2 通道在这个部署上不通。
//   - 必须 Transfer-Encoding: chunked；用 Content-Length 会被当一次性请求。
//   - 每次 Write 立即成块，不能缓冲，否则数据滞留、隧道建好但 0 字节。
package x365http

import (
	std_bufio "bufio"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	dialer     N.Dialer
	serverAddr M.Socksaddr
	path       string
	host       string
	headers    http.Header
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayX365Options, tlsConfig tls.Config) (*Client, error) {
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
	request.WriteString("User-Agent: Mozilla/5.0\r\n")
	request.WriteString("\r\n")
	if _, err = conn.Write([]byte(request.String())); err != nil {
		conn.Close()
		return nil, E.Cause(err, "write x365 request")
	}
	return &Conn{Conn: conn, reader: std_bufio.NewReaderSize(conn, 64*1024)}, nil
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
		return E.New("x365: unexpected status: ", response.Status)
	}
	c.headRead = true
	// http.Response.Body 已经内置 chunked 解码（含 trailer）。
	c.body = &bodyConn{Conn: c.Conn, reader: response.Body}
	return nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if err := c.readHead(); err != nil {
		return 0, err
	}
	return c.body.Read(p)
}

// Write 立即把数据做成一个 HTTP/1.1 chunk（不缓冲，见包注释）。
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
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
