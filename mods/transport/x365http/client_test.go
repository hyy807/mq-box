package x365http

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/mods/modoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// fakeDialer 每次 Dial 都连到本地回环上的模拟服务端。
// 用真实 TCP 而不是 net.Pipe：http.Transport 的 writeLoop/readLoop 需要
// 可缓冲的双向通道，net.Pipe 的同步语义会自锁。
type fakeDialer struct {
	addr string
}

func (d *fakeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.addr)
}

func (d *fakeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

var _ N.Dialer = (*fakeDialer)(nil)

// runFakeServer 按参考实现的线上格式校验请求，再回 HTTP/1.1 200 + chunked 应答。
func runFakeServer(server net.Conn, wantPath string, responseBody []byte, done chan error) {
	defer server.Close()
	fail := func(format string, args ...any) {
		done <- fmt.Errorf(format, args...)
	}
	reader := std_bufio.NewReader(server)
	var head strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fail("read request head: %v", err)
			return
		}
		head.WriteString(line)
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}
	if !strings.HasPrefix(head.String(), "POST "+wantPath+" HTTP/1.1\r\n") {
		fail("unexpected request line:\n%s", head.String())
		return
	}
	lower := strings.ToLower(head.String())
	for _, header := range []string{
		"content-type: application/grpc",
		"transfer-encoding: chunked",
		"user-agent: " + strings.ToLower(userAgent),
		"host: dldir1.qq.com",
	} {
		if !strings.Contains(lower, header) {
			fail("missing %q in:\n%s", header, head.String())
			return
		}
	}
	// 覆盖后的 UA 必须是 111 字节的完整 chrome UA（0x6f），
	// 简写的 Mozilla/5.0 已被服务端中间层当成非浏览器流量。
	if !strings.Contains(lower, "chrome/120.0.0.0") {
		fail("user-agent is not the full chrome UA:\n%s", head.String())
		return
	}
	sizeLine, err := reader.ReadString('\n')
	if err != nil {
		fail("read chunk size: %v", err)
		return
	}
	size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
	if err != nil {
		fail("chunk size %q: %v", sizeLine, err)
		return
	}
	payload := make([]byte, size+2)
	if _, err = io.ReadFull(reader, payload); err != nil {
		fail("read chunk body: %v", err)
		return
	}
	if !strings.HasPrefix(string(payload), "X365\x01\x01") {
		fail("handshake frame prefix %q", string(payload[:min(8, len(payload))]))
		return
	}
	// 用标准库序列化响应，保证 chunked 编码（含终止块）完全合规。
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/grpc"}},
		Body:          io.NopCloser(bytes.NewReader(responseBody)),
		ContentLength: -1,
	}
	if err = resp.Write(server); err != nil {
		fail("write response: %v", err)
		return
	}
	done <- nil
	// 保持连接可用：等对端关闭（读到 EOF）再退出，避免响应体读一半被 RST。
	_, _ = io.Copy(io.Discard, reader)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// startServer 起一个本地 TCP 监听并交给 handler 处理一条连接。
func startServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return listener.Addr().String()
}

func TestX365TransportWireFormat(t *testing.T) {
	done := make(chan error, 1)
	addr := startServer(t, func(server net.Conn) {
		runFakeServer(server, "/hk1", []byte("X365\x00hello"), done)
	})

	transport, err := NewClient(&fakeDialer{addr: addr}, M.ParseSocksaddr("bgp01.example.com:443"), modoption.X365Options{
		Host: "dldir1.qq.com",
		Path: "/hk1",
	}, tls.Config(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	conn, err := transport.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	frame := append([]byte("X365\x01\x01"), make([]byte, 16)...)
	frame = append(frame, 0x01, 0xbb, 0x02, 0x01, 'h')
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("hello"))
	if _, err = io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "hello" {
		t.Fatalf("response %q", string(buffer))
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish")
	}
}

// TestDialReturnsBeforeServerResponds 验证 Dial 不再同步等响应头：
// 服务端故意延迟发响应，Dial 必须立刻返回（上游 DialStreamOne 的行为）。
func TestDialReturnsBeforeServerResponds(t *testing.T) {
	released := make(chan struct{})
	addr := startServer(t, func(server net.Conn) {
		reader := std_bufio.NewReader(server)
		for { // 读完请求头
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimRight(line, "\r\n") == "" {
				break
			}
		}
		<-released // 卡住，不给响应
		_ = server.Close()
	})

	transport, err := NewClient(&fakeDialer{addr: addr}, M.ParseSocksaddr("bgp01.example.com:443"),
		modoption.X365Options{Host: "dldir1.qq.com", Path: "/hk1"}, tls.Config(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	dialDone := make(chan error, 1)
	go func() {
		_, err := transport.DialContext(context.Background())
		dialDone <- err
	}()

	select {
	case err := <-dialDone:
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Dial blocked waiting for the server response (should return after TCP connect)")
	}
	close(released)
}

// TestConcurrentTunnelsAndRelease 验证：
//   - 多条隧道可并发建立、各自独立收发；
//   - 关闭隧道会释放它独占的 http.Transport（上游 conn.onClose 的语义）。
//
// 注意：x365 是 stream-one（单个长 POST），一条隧道独占一个 transport，
// 这与上游 stream-one 的行为一致（上游 onClose 里同样 CloseTransport）。
func TestConcurrentTunnelsAndRelease(t *testing.T) {
	addr := startServer(t, func(server net.Conn) {
		reader := std_bufio.NewReader(server)
		// 读请求头
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimRight(line, "\r\n") == "" {
				break
			}
		}
		// 读握手 chunk
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		size, _ := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if _, err = io.CopyN(io.Discard, reader, size+2); err != nil {
			return
		}
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(bytes.NewReader([]byte("X365\x00z"))),
			ContentLength: -1,
		}
		_ = resp.Write(server)
		// 保持连接开着，模拟长隧道
		time.Sleep(3 * time.Second)
		_ = server.Close()
	})

	transport, err := NewClient(&fakeDialer{addr: addr}, M.ParseSocksaddr("bgp01.example.com:443"),
		modoption.X365Options{Host: "dldir1.qq.com", Path: "/hk1"}, tls.Config(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	const parallel = 4
	errs := make(chan error, parallel)
	start := make(chan struct{})
	for i := 0; i < parallel; i++ {
		go func(i int) {
			<-start
			conn, err := transport.DialContext(context.Background())
			if err != nil {
				errs <- fmt.Errorf("dial %d: %w", i, err)
				return
			}
			frame := append([]byte("X365\x01\x01"), make([]byte, 16)...)
			frame = append(frame, 0x01, 0xbb, 0x02, 0x01, 'h')
			if _, err = conn.Write(frame); err != nil {
				errs <- fmt.Errorf("write %d: %w", i, err)
				return
			}
			buffer := make([]byte, len("z"))
			if _, err = io.ReadFull(conn, buffer); err != nil {
				errs <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if string(buffer) != "z" {
				errs <- fmt.Errorf("tunnel %d got %q", i, string(buffer))
				return
			}
			if err = conn.Close(); err != nil {
				errs <- fmt.Errorf("close %d: %w", i, err)
				return
			}
			errs <- nil
		}(i)
	}
	close(start)
	for i := 0; i < parallel; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	// 全部隧道关闭后，ReuseManager 应报告没有活跃 entry 占用。
	transport.reuse.mu.Lock()
	defer transport.reuse.mu.Unlock()
	for _, entry := range transport.reuse.entries {
		if entry.openUsage.Load() != 0 {
			t.Fatalf("entry still in use after Close: openUsage=%d", entry.openUsage.Load())
		}
	}
}
