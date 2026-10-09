package modoption

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// LightXtremeOutboundOptions is AnyTLS with the LightXtreme private
// authentication. It is a separate type, upstream `anytls` is untouched.
type LightXtremeOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	ModTLSOptionsContainer
	Password                 string             `json:"password,omitempty"`
	PlatformMarker           uint8              `json:"platform_marker,omitempty"`
	IdleSessionCheckInterval badoption.Duration `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                `json:"min_idle_session,omitempty"`
	ClientMetadata           string             `json:"client_metadata,omitempty"`
}

// FastUPOutboundOptions is Trojan whose key is derived as
// hex(md5(password + mpw)). Upstream `trojan` is untouched.
type FastUPOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	Password string             `json:"password"`
	Mpw      string             `json:"mpw,omitempty"`
	Network  option.NetworkList `json:"network,omitempty"`
	ModTLSOptionsContainer
	Multiplex *option.OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *option.V2RayTransportOptions    `json:"transport,omitempty"`
}

// VLESSXHTTPOutboundOptions is VLESS carried over XHTTP (HTTP/2). Upstream
// `vless` and the upstream v2ray transports are untouched.
type VLESSXHTTPOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	UUID           string             `json:"uuid"`
	Network        option.NetworkList `json:"network,omitempty"`
	PacketEncoding *string            `json:"packet_encoding,omitempty"`
	ModTLSOptionsContainer
	XHTTP XHTTPOptions `json:"xhttp"`
}

// X365Options configures the x365 carrier: an HTTP/1.1 POST with
// Transfer-Encoding: chunked over REALITY/TLS.
type X365Options struct {
	Host    string               `json:"host,omitempty"`
	Path    string               `json:"path,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}

// X365OutboundOptions is the饿饭/365VPN private `x365` outbound: a VLESS-style
// UUID handshake wrapped in the maker-defined X365 frame on an HTTP/1.1 chunked
// carrier. Upstream `vless` / `xhttp` are untouched.
type X365OutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	UUID           string             `json:"uuid"`
	Network        option.NetworkList `json:"network,omitempty"`
	PacketEncoding *string            `json:"packet_encoding,omitempty"`
	ModTLSOptionsContainer
	X365 X365Options `json:"x365"`
}
