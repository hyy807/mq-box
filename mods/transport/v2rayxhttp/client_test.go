package v2rayxhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestStreamOneSessionTransportReuse(t *testing.T) {
	c := &Client{transport: &http2.Transport{}, streamTransport: &http2.Transport{}, mode: "stream-one"}
	first, err := c.sessionTransport()
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.sessionTransport()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first == c.transport {
		t.Fatal("stream-one sessions must share the dedicated HTTP/2 transport")
	}
	c.mode = "packet-up"
	shared, err := c.sessionTransport()
	if err != nil {
		t.Fatal(err)
	}
	if shared != c.transport {
		t.Fatal("packet-up must keep its reusable HTTP/2 transport")
	}
}

func TestClosedResponseBodyIsLocalClose(t *testing.T) {
	body := &blockingBody{started: make(chan struct{}), done: make(chan struct{})}
	c := &connection{body: body, initial: result{body: body}, done: make(chan struct{}), cancel: func() {}}
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("response read did not start")
	}
	c.Close()
	select {
	case err := <-result:
		if err != net.ErrClosed {
			t.Fatalf("local close returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("response read did not unblock")
	}
}

type blockingBody struct {
	started chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (b *blockingBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.done
	return 0, errors.New("http2: response body closed")
}
func (b *blockingBody) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	return nil
}
func TestRequestFraming(t *testing.T) {
	c := &Client{base: url.URL{Scheme: "https", Host: "edge.example:443", Path: "/custom"}, host: "dldir1.qq.com", headers: http.Header{"X-Test": []string{"ok"}}}
	r, err := c.request(context.Background(), http.MethodPost, c.base, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if r.URL.Host != "edge.example:443" || r.URL.Path != "/custom" || r.Host != "dldir1.qq.com" || r.Header.Get("X-Test") != "ok" || r.Header.Get("Content-Type") != "application/grpc" {
		t.Fatalf("unexpected request: %+v", r)
	}
	if !strings.Contains(r.Header.Get("Referer"), "x_padding=") {
		t.Fatal("missing xhttp padding")
	}
	if r.Header.Get("Host") != "" {
		t.Fatal("Host must be request authority, not duplicate header")
	}
}

func TestNormalizeXHTTPPath(t *testing.T) {
	for original, expected := range map[string]string{
		"/ru81":  "/ru81/",
		"/ru81/": "/ru81/",
		"/":      "/",
	} {
		u := url.URL{Path: original}
		normalizeXHTTPPath(&u)
		if u.Path != expected {
			t.Errorf("path %q: got %q, want %q", original, u.Path, expected)
		}
	}
}

func TestPacketPath(t *testing.T) {
	c := &Client{base: url.URL{Scheme: "https", Host: "edge.example", Path: "/path/session"}, host: "dldir1.qq.com", headers: make(http.Header)}
	r, err := c.request(context.Background(), http.MethodGet, c.base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.URL.Path != "/path/session" || r.Host != "dldir1.qq.com" {
		t.Fatalf("unexpected download request: %+v", r)
	}
}
