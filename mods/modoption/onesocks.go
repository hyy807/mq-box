package modoption

import (
	"github.com/sagernet/sing-box/option"
)

// OneSocksOutboundOptions is the configuration contract of the Heysocks
// `type: os` (OneSocks) outbound: a password protected AES-CTR stream over a
// plain TCP connection. In contrast to `xhttp` there is no TLS front door, so
// the transport is reachable from any source address.
type OneSocksOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	// Name is the provider node label, kept as-is.
	Name string `json:"name,omitempty"`
	// Password is used as raw bytes, both for the MD5 chain key and for H.
	Password string `json:"password"`
	// Cipher names the stream algorithm; the provider nodes use aes-128-ctr.
	Cipher string `json:"cipher,omitempty"`
	// PaddingLen is "min-max", e.g. "8-64" which yields 8..63 bytes.
	PaddingLen string `json:"padding_len,omitempty"`
	// UDP is kept for schema compatibility. UDP framing is not implemented, so
	// UDP traffic is rejected instead of being silently dropped.
	UDP bool `json:"udp,omitempty"`
	// Network lists the supported networks, defaults to ["tcp"].
	Network option.NetworkList `json:"network,omitempty"`
}
