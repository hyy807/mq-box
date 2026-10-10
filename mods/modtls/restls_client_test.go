package modtls

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	restls "github.com/metacubex/restls-client-go"
	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/option"
)

func TestRESTLSOptionsAndConfig(t *testing.T) {
	var options modoption.ModTLSOptions
	if err := json.Unmarshal([]byte(`{"enabled":true,"server_name":"example.org","restls":{"password":"secret","version_hint":"tls13","restls_script":"250<1","fingerprint":"firefox"}}`), &options); err != nil {
		t.Fatal(err)
	}
	config, err := newRESTLSClient(context.Background(), "", options.OutboundTLSOptions, options.RESTLS)
	if err != nil {
		t.Fatal(err)
	}
	client := config.(*RESTLSClientConfig)
	peer, wire := net.Pipe()
	defer peer.Close()
	conn, err := client.Client(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if client.config.ServerName != "example.org" || client.clientID.Client != restls.HelloFirefox_Auto.Client || len(client.config.RestlsSecret) != 32 || len(client.config.RestlsScript) != 1 {
		t.Fatal("RESTLS configuration differs from upstream constructor")
	}
	clone := client.Clone()
	clone.SetServerName("changed.example")
	if client.ServerName() != "example.org" {
		t.Fatal("clone changed original SNI")
	}
	if _, ok := conn.(*restlsConn); !ok {
		t.Fatal("RESTLS must use the RESTLS wire implementation")
	}
}

func TestRESTLSRejectInvalidVersion(t *testing.T) {
	_, err := newRESTLSClient(context.Background(), "example.org", option.OutboundTLSOptions{}, &modoption.RESTLSOptions{Password: "secret", VersionHint: "1.3"})
	if err == nil {
		t.Fatal("RESTLS version hint must use tls12 or tls13")
	}
}
