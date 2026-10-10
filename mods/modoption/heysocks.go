package modoption

import (
	"github.com/sagernet/sing-box/option"
)

// HeysocksXhttpOutboundOptions is the configuration contract of the Heysocks
// (just4test) `type: xhttp` outbound.
//
// The reference config hands every node a "cipher:password" pair
// (password = "<hex seed>:<hex extra>"), the padding window, and an HTTP/2
// carrier whose SNI, Host and path are separate values.
type HeysocksXhttpOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	// Name is the node label from the provider JSON, kept as-is.
	Name string `json:"name,omitempty"`
	// Cipher is a name from the reference algorithm table; DUMMY disables
	// encryption.
	Cipher string `json:"cipher,omitempty"`
	// Password is "<hex seed>:<hex extra>". The seed is used as ASCII text.
	Password string `json:"password"`
	// PaddingLen is "min-max".
	PaddingLen string `json:"padding_len,omitempty"`
	// Clover and FakeNet are accepted and preserved, their wire semantics are
	// not established by the specification.
	Clover  int             `json:"clover,omitempty"`
	FakeNet *FakeNetOptions `json:"fake_net,omitempty"`
	// UDP / UDPOverTCP are capability flags; UDP framing is not implemented.
	UDP        bool `json:"udp,omitempty"`
	UDPOverTCP bool `json:"udp_over_tcp,omitempty"`
	// DebugWire dumps the first wire bytes (header block and first response
	// bytes) into the application log. Diagnostic only.
	DebugWire bool `json:"debug_wire,omitempty"`
	// WireVariant selects the header block layout: "default" (specification
	// section 3.2, including the 128 byte random region), "rand-separated",
	// "no-extra", or "legacy" (the pre-specification layout, kept for
	// bisection on a device).
	WireVariant string `json:"wire_variant,omitempty"`
	// ReadVariant selects the downstream framing: "iv" or "hmac-iv".
	ReadVariant string `json:"read_variant,omitempty"`
	// Host and Path are the HTTP/2 request carrier values (xhttp-opts).
	Host    string             `json:"host,omitempty"`
	Path    string             `json:"path,omitempty"`
	Scheme  string             `json:"scheme,omitempty"`
	Network option.NetworkList `json:"network,omitempty"`
	option.OutboundTLSOptionsContainer
}

type FakeNetOptions struct {
	TCP string `json:"tcp,omitempty"`
	UDP string `json:"udp,omitempty"`
}
