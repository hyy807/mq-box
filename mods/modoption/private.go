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


// VLESSX365OutboundOptions is the 饿饭/365VPN X365 deployment expressed on the
// upstream VLESS protocol: the standard sing-vmess VLESS frame (Version 0x00 +
// UUID + addons + command) over the XHTTP (HTTP/2) carrier. It reuses the
// upstream vless semantics and the private XHTTP transport instead of defining
// a private wire protocol, so upstream `protocol/vless` is untouched.
type VLESSX365OutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	UUID           string             `json:"uuid"`
	Network        option.NetworkList `json:"network,omitempty"`
	PacketEncoding *string            `json:"packet_encoding,omitempty"`
	ModTLSOptionsContainer
	XHTTP XHTTPOptions `json:"xhttp"`
}
