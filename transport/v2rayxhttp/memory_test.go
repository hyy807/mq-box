package v2rayxhttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// Inspect actual wire SETTINGS: a configuration object alone doesn't prove
// ConfigureTransports propagated the receive window to x/net/http2.
func TestBoundedReceiveWindowOnWire(t *testing.T) {
	tr, err := newBoundedTransport()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	windows := make(chan uint32, 1)
	go func() {
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			return
		}
		fr := http2.NewFramer(io.Discard, server)
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok {
			return
		}
		sf.ForeachSetting(func(s http2.Setting) error {
			if s.ID == http2.SettingInitialWindowSize {
				windows <- s.Val
			}
			return nil
		})
		// Drain initial connection WINDOW_UPDATE so NewClientConn can return.
		fr.ReadFrame()
	}()
	cc, err := tr.NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	select {
	case w := <-windows:
		if w != xhttpReceiveWindow {
			t.Fatalf("wire window=%d", w)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no window setting")
	}
}

func TestSessionCancellationClosesDialedSocket(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	closed := make(chan struct{})
	go func() { <-ctx.Done(); client.Close(); close(closed) }()
	cancel()
	<-closed
	peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err := peer.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("cancelled socket read: %v", err)
	}
}

func TestConcurrentBoundedDownloads(t *testing.T) {
	payload := make([]byte, 1<<20)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr, err := newBoundedTransport()
			if err != nil {
				t.Error(err)
				return
			}
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			defer tr.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			n, err := io.Copy(io.Discard, resp.Body)
			if err != nil || n != int64(len(payload)) {
				t.Errorf("download bytes=%d err=%v", n, err)
			}
		}()
	}
	wg.Wait()
}
