package x365http

import (
	std_bufio "bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeDialer struct {
	conn net.Conn
}

func (d *fakeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d *fakeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

var _ N.Dialer = (*fakeDialer)(nil)

// runFakeServer 按参考实现的线上格式校验请求，再回 HTTP/1.1 200 + chunked 应答。
func runFakeServer(server net.Conn, wantPath string, responseBody []byte, done chan error) {
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
	for _, header := range []string{"content-type: application/grpc", "transfer-encoding: chunked", "user-agent: mozilla/5.0", "host: dldir1.qq.com"} {
		if !strings.Contains(lower, header) {
			fail("missing %q in:\n%s", header, head.String())
			return
		}
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
	// 一次性写出（net.Pipe 的 Write 要等对端读完，分多次写会卡住）
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n" +
		strconv.FormatInt(int64(len(responseBody)), 16) + "\r\n" + string(responseBody) + "\r\n"
	if _, err = server.Write([]byte(response)); err != nil {
		fail("write response: %v", err)
		return
	}
	done <- nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestX365TransportWireFormat(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go runFakeServer(server, "/hk1", []byte("X365\x00hello"), done)

	var tlsConfig tls.Config
	transport, err := NewClient(context.Background(), &fakeDialer{conn: client}, M.ParseSocksaddr("bgp01.example.com:443"), option.V2RayX365Options{
		Host: "dldir1.qq.com",
		Path: "/hk1",
	}, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte("X365\x01\x01"), make([]byte, 16)...)
	frame = append(frame, 0x01, 0xbb, 0x02, 0x01, 'h')
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("X365\x00hello"))
	if _, err = io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "X365\x00hello" {
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
