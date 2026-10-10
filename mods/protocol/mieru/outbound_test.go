package mieru

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestBuildProfile(t *testing.T) {
	base := modoption.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 12345},
		Transport:     "TCP", Username: "alice", Password: "secret",
	}
	profile, err := buildProfile("test", base)
	if err != nil {
		t.Fatal(err)
	}
	if profile.GetServers()[0].GetDomainName() != "example.com" || profile.GetServers()[0].GetPortBindings()[0].GetPort() != 12345 {
		t.Fatalf("unexpected profile: %v", profile)
	}
	base.Server = "2001:db8::1"
	base.ServerPort = 0
	base.PortRange = "10000-20000"
	base.Transport = "UDP"
	profile, err = buildProfile("test", base)
	if err != nil {
		t.Fatal(err)
	}
	if profile.GetServers()[0].GetIpAddress() != "2001:db8::1" || profile.GetServers()[0].GetPortBindings()[0].GetPortRange() != "10000-20000" {
		t.Fatalf("unexpected profile: %v", profile)
	}
	for _, bad := range []string{"", "0-1", "1-65536", "2-1", "1-2garbage", "a-b", "1-2-3"} {
		base.PortRange = bad
		if bad == "" {
			base.ServerPort = 12345
		}
		if bad != "" {
			base.ServerPort = 0
		}
		_, err := buildProfile("test", base)
		if bad != "" && err == nil {
			t.Errorf("accepted bad range %q", bad)
		}
	}
	base.PortRange = "1-2"
	base.Transport = "invalid"
	if _, err := buildProfile("test", base); err == nil {
		t.Fatal("accepted invalid transport")
	}
	base.Transport = "TCP"
	base.Multiplexing = "invalid"
	if _, err := buildProfile("test", base); err == nil {
		t.Fatal("accepted invalid multiplexing")
	}
	base.Multiplexing = ""
	base.HandshakeMode = "invalid"
	if _, err := buildProfile("test", base); err == nil {
		t.Fatal("accepted invalid handshake mode")
	}
}

func TestAddressSpec(t *testing.T) {
	for _, test := range []struct{ input, fqdn, ip string }{
		{"example.com:443", "example.com", ""},
		{"[2001:db8::1]:443", "", "2001:db8::1"},
		{"192.0.2.1:443", "", "192.0.2.1"},
	} {
		spec := addressSpec(M.ParseSocksaddr(test.input))
		if spec.FQDN != test.fqdn || spec.IP.String() != net.ParseIP(test.ip).String() && test.ip != "" || spec.Port != 443 {
			t.Errorf("%q: unexpected spec %+v", test.input, spec)
		}
	}
}

func TestPacketDialerRejectsDomain(t *testing.T) {
	var d packetDialer
	if _, err := d.ListenPacket(context.Background(), "udp", "", "example.com:443"); err == nil {
		t.Fatal("accepted unresolved packet endpoint")
	}
}
