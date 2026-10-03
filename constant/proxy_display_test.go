package constant

import "testing"

func TestOneSocksDisplayName(t *testing.T) {
	for _, proxyType := range []string{TypeOneSocks, TypeOneSocksLong} {
		if got := ProxyDisplayName(proxyType); got != "OneSocks" {
			t.Fatalf("ProxyDisplayName(%q) = %q, want OneSocks", proxyType, got)
		}
	}
	if got := ProxyDisplayName("unregistered-protocol"); got != "Unknown" {
		t.Fatalf("unknown protocol display = %q, want Unknown", got)
	}
}
