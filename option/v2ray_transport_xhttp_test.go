package option

import (
	"encoding/json"
	"testing"
)

func TestV2RayXHTTPOptionsJSON(t *testing.T) {
	raw := []byte(`{"type":"xhttp","mode":"auto","path":"/x365","headers":{"Host":"dldir1.qq.com"}}`)
	var opts V2RayTransportOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.Type != "xhttp" || opts.XHTTPOptions.Mode != "auto" || opts.XHTTPOptions.Path != "/x365" || opts.XHTTPOptions.Headers.Build().Get("Host") != "dldir1.qq.com" {
		t.Fatalf("unexpected options: %+v", opts)
	}
	encoded, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	var restored V2RayTransportOptions
	if err = json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.XHTTPOptions.Headers.Build().Get("Host") != "dldir1.qq.com" {
		t.Fatalf("lost Host: %s", encoded)
	}
}
