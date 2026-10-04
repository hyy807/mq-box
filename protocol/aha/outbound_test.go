package aha

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestConfigurationLimit(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, nil, "test", option.AHAOutboundOptions{})
	if err == nil || (!strings.Contains(err.Error(), "username and password") && !strings.Contains(err.Error(), "endpoint")) {
		t.Fatalf("%v", err)
	}
}
func TestRegistrationAndUnsupportedNetworks(t *testing.T) {
	registry := outbound.NewRegistry()
	RegisterOutbound(registry)
	if C.ProxyDisplayName(C.TypeAHA) != "AHAspeed" {
		t.Fatal("display name")
	}
	h := new(Outbound)
	if _, err := h.ListenPacket(context.Background(), M.Socksaddr{}); err == nil {
		t.Fatal("UDP accepted")
	}
	if _, err := h.DialContext(context.Background(), "udp", M.Socksaddr{}); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("%v", err)
	}
	if _, err := h.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil || !strings.Contains(err.Error(), "bridge") {
		t.Fatalf("%v", err)
	}
}
