package aha

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

type testHubDialer struct{}

func (testHubDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}
func (testHubDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unused")
}

func TestDiscoverAcceptsTokenReturnedByAccessEvenIfSameAsSignin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cmd") {
		case "signin":
			fmt.Fprint(w, `{"user":{"uid":123},"token":{"token":"same-value"}}`)
		case "access":
			fmt.Fprint(w, `{"token":{"token":"same-value"}}`)
		case "node":
			fmt.Fprint(w, `{"node":{"vip":{"hk":{"test":{"host":"example.baidu.com"}}}}}`)
		default:
			t.Errorf("unexpected command")
		}
	}))
	defer server.Close()
	h := &HubDiscovery{Dialer: testHubDialer{}, BaseURL: server.URL + "/light/dispatch/v2"}
	_, err := h.Discover(context.Background(), "test", "test", "hk")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverAllReturnsEveryUsableNode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cmd") {
		case "signin":
			fmt.Fprint(w, `{"user":{"uid":123},"token":{"token":"same-value"}}`)
		case "access":
			fmt.Fprint(w, `{"token":{"token":"same-value"}}`)
		case "node":
			fmt.Fprint(w, `{"node":{"vip":{"hk":{"one":{"host":"one.baidu.com","port":"3306"},"two":{"host":"two.baidu.com","port":"3306"},"duplicate":{"host":"one.baidu.com","port":"3306"}}}}}`)
		default:
			t.Errorf("unexpected command")
		}
	}))
	defer server.Close()
	h := &HubDiscovery{Dialer: testHubDialer{}, BaseURL: server.URL + "/light/dispatch/v2"}
	endpoints, err := h.DiscoverAll(context.Background(), "test", "test", "hk")
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("unexpected endpoints: %+v", endpoints)
	}
	if endpoints[0].Handshake.TunnelIP == endpoints[1].Handshake.TunnelIP {
		t.Fatalf("callers must not share a tunnel address: %+v", endpoints)
	}
}

// Many endpoints start at once and every login invalidates the previous session
// token, so a second discovery for the same account must reuse the first result.
func TestDiscoverAllCachesOneLoginPerRegion(t *testing.T) {
	var signins int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cmd") {
		case "signin":
			mu.Lock()
			signins++
			mu.Unlock()
			fmt.Fprint(w, `{"user":{"uid":123},"token":{"token":"same-value"}}`)
		case "access":
			fmt.Fprint(w, `{"token":{"token":"same-value"}}`)
		case "node":
			fmt.Fprint(w, `{"node":{"vip":{"hk":{"one":{"host":"one.baidu.com","port":"3306"}}}}}`)
		default:
			t.Errorf("unexpected command")
		}
	}))
	defer server.Close()
	h := &HubDiscovery{Dialer: testHubDialer{}, BaseURL: server.URL + "/light/dispatch/v2"}
	first, err := h.DiscoverAll(context.Background(), "cache-user", "cache-pass", "hk")
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.DiscoverAll(context.Background(), "cache-user", "cache-pass", "hk")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if signins != 1 {
		t.Fatalf("expected one login for a repeated discovery, got %d", signins)
	}
	if len(second) != len(first) {
		t.Fatalf("cached discovery changed shape: %+v", second)
	}
	if second[0].Handshake.TunnelIP == first[0].Handshake.TunnelIP {
		t.Fatal("a cached node must still be given a per-caller tunnel address")
	}
}
