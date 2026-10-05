package aha

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
}
