package option

// OppaOutboundOptions is the configuration contract of the Oppa / sslhop
// outbound. The reference client configuration keeps Clash style fields
// (password, udp, pre-connect, sni, skip-cert-verify); here they are mapped
// explicitly instead of relying on dashed JSON keys.
type OppaOutboundOptions struct {
	DialerOptions
	ServerOptions
	// Password is sent raw and must be exactly 32 bytes after UTF-8 encoding.
	Password string `json:"password"`
	// PreConnect is the number of idle TLS connections kept warm. 0 disables
	// the pool and dials on demand.
	PreConnect int `json:"pre_connect,omitempty"`
	// UDP enables the UDP-over-TLS channel. It is equivalent to adding "udp"
	// to network.
	UDP bool `json:"udp,omitempty"`
	// Network lists the supported networks, defaults to ["tcp"], or
	// ["tcp", "udp"] when UDP is enabled.
	Network NetworkList `json:"network,omitempty"`
	// TLS holds the optional extension mode. The vendor compatible mode (no
	// SNI, no ALPN, no certificate verification) is the default and is used
	// when the container is absent.
	OutboundTLSOptionsContainer
}
