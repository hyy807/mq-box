package v2rayxhttp

import (
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

type fakeALPNConfig struct {
	next []string
}

func (c *fakeALPNConfig) NextProtos() []string     { return c.next }
func (c *fakeALPNConfig) SetNextProtos(p []string) { c.next = p }

// The profile's own ALPN list must survive: the deployment rejects an h2-only
// ClientHello with a no_application_protocol alert, so rewriting the list to
// [h2] made every XHTTP/REALITY outbound fail against that server.
func TestNormalizeALPNKeepsProfileList(t *testing.T) {
	c := &fakeALPNConfig{next: []string{http2.NextProtoTLS, "http/1.1"}}
	if err := normalizeALPN(c); err != nil {
		t.Fatal(err)
	}
	if len(c.next) != 2 || c.next[0] != http2.NextProtoTLS || c.next[1] != "http/1.1" {
		t.Fatalf("profile ALPN list was rewritten: %v", c.next)
	}
}

func TestNormalizeALPNFillsEmptyAndH2Only(t *testing.T) {
	for _, in := range [][]string{nil, {http2.NextProtoTLS}} {
		c := &fakeALPNConfig{next: in}
		if err := normalizeALPN(c); err != nil {
			t.Fatal(err)
		}
		if len(c.next) != 2 || c.next[0] != http2.NextProtoTLS || c.next[1] != "http/1.1" {
			t.Fatalf("in=%v -> %v", in, c.next)
		}
	}
}

func TestNormalizeALPNKeepsH2First(t *testing.T) {
	c := &fakeALPNConfig{next: []string{http2.NextProtoTLS, "http/1.1", "h3"}}
	if err := normalizeALPN(c); err != nil {
		t.Fatal(err)
	}
	if len(c.next) != 3 || c.next[0] != http2.NextProtoTLS {
		t.Fatalf("h2 must stay first: %v", c.next)
	}
}

func TestNormalizeALPNRejectsMissingH2(t *testing.T) {
	c := &fakeALPNConfig{next: []string{"http/1.1"}}
	err := normalizeALPN(c)
	if err == nil || !strings.Contains(err.Error(), "h2 is missing") {
		t.Fatalf("unexpected result: %v", err)
	}
}
