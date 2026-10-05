package aha

import (
	"net/netip"
	"testing"
	"time"
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

// A node list must be cheap while unused: the flow dispatcher still has to learn
// every node's own address space before any data plane exists, so PortAddresses
// answers from the offered address instead of the missing device.
func TestPortAddressesBeforeDataPlane(t *testing.T) {
	address := netip.MustParseAddr("10.10.10.77")
	endpoint := &Endpoint{address: address}
	inet4, inet6 := endpoint.PortAddresses()
	if inet4 != address {
		t.Fatalf("inet4 = %v, want %v", inet4, address)
	}
	if inet6.IsValid() {
		t.Fatalf("inet6 = %v, want invalid on an IPv4-only tunnel", inet6)
	}
}

// Registering more live data planes than the idle budget recycles the oldest idle
// node instead of letting one Go IP stack per node accumulate.
func TestOldestIdleDataPlaneIsRecycled(t *testing.T) {
	liveDataPlanes.mu.Lock()
	liveDataPlanes.list = nil
	liveDataPlanes.mu.Unlock()
	defer func() {
		liveDataPlanes.mu.Lock()
		liveDataPlanes.list = nil
		liveDataPlanes.mu.Unlock()
	}()
	for index := 0; index < ahaMaxIdleDataPlanes+2; index++ {
		endpoint := &Endpoint{}
		endpoint.lastUsed.Store(time.Now().Add(-time.Duration(ahaMaxIdleDataPlanes+2-index) * time.Minute).UnixNano())
		registerLiveDataPlane(endpoint)
	}
	liveDataPlanes.mu.Lock()
	live := len(liveDataPlanes.list)
	liveDataPlanes.mu.Unlock()
	if live > ahaMaxIdleDataPlanes {
		t.Fatalf("live data planes = %d, want at most %d", live, ahaMaxIdleDataPlanes)
	}
}
