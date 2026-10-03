package option

import (
	"encoding/json"
	"testing"
)

func TestTrojanOutboundMpwJSON(t *testing.T) {
	raw := []byte(`{"type":"trojan","server":"node.example","server_port":443,"password":"account-password","mpw":"shared-secret","tls":{"enabled":true,"server_name":"www.example.com","insecure":true},"multiplex":{"enabled":true}}`)
	var opts TrojanOutboundOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.Mpw != "shared-secret" {
		t.Fatalf("unexpected mpw: %q", opts.Mpw)
	}
	encoded, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	var restored TrojanOutboundOptions
	if err = json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Mpw != "shared-secret" {
		t.Fatalf("lost mpw: %s", encoded)
	}
}

func TestTrojanOutboundWithoutMpwStaysClean(t *testing.T) {
	raw := []byte(`{"type":"trojan","server":"node.example","server_port":443,"password":"account-password"}`)
	var opts TrojanOutboundOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.Mpw != "" {
		t.Fatalf("unexpected mpw: %q", opts.Mpw)
	}
	encoded, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err = json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	if _, loaded := generic["mpw"]; loaded {
		t.Fatalf("mpw must be omitted when empty: %s", encoded)
	}
}
