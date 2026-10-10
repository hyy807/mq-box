package v2rayxhttp

import (
	"strings"
	"testing"
)

// The diagnostic path must never feed []string to sing's format.ToString:
// that formatter panics and kills the iOS VPN extension.
func TestALPNErrorDoesNotPanic(t *testing.T) {
	err := alpnError("http/1.1", []string{"h2"})
	if err == nil || !strings.Contains(err.Error(), `negotiated="http/1.1"`) || !strings.Contains(err.Error(), `offered=["h2"]`) {
		t.Fatalf("unexpected ALPN error: %v", err)
	}
}
