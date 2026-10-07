package modoption

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// ModTLSOptions is the TLS block of the private protocols. It embeds the
// upstream OutboundTLSOptions unchanged and only adds the extra handshakes the
// private protocols need, so upstream TLS options are never edited.
type ModTLSOptions struct {
	option.OutboundTLSOptions
	JLS    *JLSOptions    `json:"jls,omitempty"`
	RESTLS *RESTLSOptions `json:"restls,omitempty"`
}

type RESTLSOptions struct {
	Password     string `json:"password,omitempty"`
	VersionHint  string `json:"version_hint,omitempty"`
	RESTLSScript string `json:"restls_script,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
}

type JLSOptions struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ModTLSOptionsContainer struct {
	TLS *ModTLSOptions `json:"tls,omitempty"`
}

// XHTTPOptions configures the XHTTP carrier of the vless-xhttp outbound.
type XHTTPOptions struct {
	Host    string               `json:"host,omitempty"`
	Path    string               `json:"path,omitempty"`
	Mode    string               `json:"mode,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}
