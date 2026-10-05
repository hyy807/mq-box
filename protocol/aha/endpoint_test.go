package aha

import (
	"net/netip"
	"testing"
)

// A fake address is meaningful only inside this client's router; the peer NATs
// real addresses, so a fake one must never be dialled through the tunnel.
func TestFakeAddressIsNeverTunnelled(t *testing.T) {
	for _, address := range []string{"198.18.0.1", "198.18.255.254", "198.19.0.1", "198.19.255.255"} {
		if !isFakeAddress(netip.MustParseAddr(address)) {
			t.Fatalf("%s was not recognised as a fake address", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "198.17.255.255", "198.20.0.1", "223.5.5.5", "8.8.8.8"} {
		if isFakeAddress(netip.MustParseAddr(address)) {
			t.Fatalf("%s was wrongly treated as a fake address", address)
		}
	}
}

func TestTunnelConfigurationBindsTheAcceptedAddress(t *testing.T) {
	address := netip.MustParseAddr("10.10.10.55")
	configuration := (&Endpoint{}).configuration(address)
	if len(configuration.Address) != 1 {
		t.Fatalf("addresses = %v", configuration.Address)
	}
	if !configuration.Address[0].Addr().Is4() || configuration.Address[0].Bits() != 32 {
		t.Fatalf("unexpected prefix %v", configuration.Address[0])
	}
	if configuration.Address[0].Addr() != address {
		t.Fatalf("prefix address = %v", configuration.Address[0].Addr())
	}
	if !configuration.BlockIPv6 {
		t.Fatal("IPv6 must stay blocked on this IPv4-only tunnel")
	}
}
