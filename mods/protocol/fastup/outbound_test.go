package fastup

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/mods/modoption"
)

// FastUP nodes are provisioned as "<uuid>" plus a salt (mpw); the key must be
// hex(md5(password + salt)).
func TestDerivePassword(t *testing.T) {
	const uuid, salt = "3ab9e5b8-3d07-4e0d-98e2-adfa99f2259f", "nya20241209"
	sum := md5.Sum([]byte(uuid + salt))
	if got := DerivePassword(uuid, salt); got != hex.EncodeToString(sum[:]) || len(got) != 32 {
		t.Fatalf("unexpected derived password %q", got)
	}
	if DerivePassword(uuid+"#fastup", salt) == DerivePassword(uuid, salt) {
		t.Fatal(`a "#fastup" suffix must change the derived key`)
	}
	if got := DerivePassword("plain", ""); got != "plain" {
		t.Fatalf("empty mpw must pass the password through, got %q", got)
	}
}

func TestOptionsJSON(t *testing.T) {
	raw := []byte(`{"server":"node.example","server_port":443,"password":"p","mpw":"s","tls":{"enabled":true,"server_name":"www.example.com","insecure":true},"multiplex":{"enabled":true}}`)
	var opts modoption.FastUPOutboundOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.Mpw != "s" || opts.TLS == nil || !opts.TLS.Enabled || opts.TLS.ServerName != "www.example.com" || opts.Multiplex == nil || !opts.Multiplex.Enabled {
		t.Fatalf("options not decoded: %+v", opts)
	}
}
