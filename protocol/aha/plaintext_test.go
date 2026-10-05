package aha

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/aha"
)

type stubDiscovery struct {
	found  T.Endpoint
	region string
}

func (s *stubDiscovery) Discover(_ context.Context, _, _, region string) (T.Endpoint, error) {
	s.region = region
	return s.found, nil
}

// A plaintext node must produce its candidate directly from the profile: no node
// list lookup, no per-region discovery, only the account session.
func TestPlaintextNodeNeedsNoNodeLookup(t *testing.T) {
	discovery := &stubDiscovery{found: T.Endpoint{
		Backend: "ignored.wishadmin.com",
		Port:    443,
		Node:    "ignored",
		Handshake: T.HandshakeOptions{
			Host: "ignored.baidu.com", UID: "u", AccessToken: "token", Device: "d",
			Platform: "windows", Version: "3.13.0", TunnelIP: "10.10.10.9", TunnelGateway: T.TunnelGateway,
		},
	}}
	outbound, err := newTunnel(context.Background(), nil, "test", option.AHAEndpointOptions{
		Username: "u", Password: "p",
		Backend: "dubai1.wishadmin.com", Host: "dubai1.baidu.com", Port: 3306,
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound.discovery = discovery
	candidates, err := outbound.candidates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected exactly the plaintext node, got %+v", candidates)
	}
	endpoint := candidates[0]
	if endpoint.Backend != "dubai1.wishadmin.com" || endpoint.Port != 3306 {
		t.Fatalf("plaintext entry not used: %+v", endpoint)
	}
	if endpoint.Handshake.Host != "dubai1.baidu.com" {
		t.Fatalf("camouflage host not used: %q", endpoint.Handshake.Host)
	}
	if endpoint.Handshake.AccessToken != "token" || endpoint.Handshake.UID != "u" {
		t.Fatalf("account session not applied: %+v", endpoint.Handshake)
	}
}

func TestPlaintextNodeRequiresBothFields(t *testing.T) {
	outbound, err := newTunnel(context.Background(), nil, "test", option.AHAEndpointOptions{
		Username: "u", Password: "p", Backend: "dubai1.wishadmin.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound.discovery = &stubDiscovery{}
	if _, err = outbound.candidates(context.Background()); err == nil {
		t.Fatal("a plaintext node without its camouflage host must be rejected")
	}
}
