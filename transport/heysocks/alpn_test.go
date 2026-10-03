//go:build with_utls

package heysocks

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/net/http2"
)

// TestAlpnNegotiationSetup mirrors what the outbound does, so a failure here
// points at the TLS config rather than at the carrier.
func TestAlpnNegotiationSetup(t *testing.T) {
	config, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       context.Background(),
		Logger:        logger.NOP(),
		ServerAddress: "apple.com",
		Options: option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "apple.com",
			Insecure:   true,
			ALPN:       []string{"h2"},
			UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		},
	})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}
	t.Logf("config type: %T", config)
	clone := config.Clone()
	t.Logf("clone type : %T", clone)
	t.Logf("initial next protos: %v", clone.NextProtos())
	if strict, ok := clone.(interface{ SetNextProtosOnly([]string) }); ok {
		t.Logf("SetNextProtosOnly available")
		strict.SetNextProtosOnly([]string{http2.NextProtoTLS})
	} else {
		t.Logf("SetNextProtosOnly NOT available, using SetNextProtos")
		clone.SetNextProtos([]string{http2.NextProtoTLS})
	}
	got := clone.NextProtos()
	t.Logf("after set         : %v", got)
	fmt.Println("next protos:", got)
	// The uTLS Chrome profile keeps http/1.1 next to h2 like Chrome itself; the
	// carrier enforces that the negotiated protocol is h2.
	if !slices.Contains(got, http2.NextProtoTLS) {
		t.Fatalf("h2 missing from the offered ALPN list: %v", got)
	}
}
