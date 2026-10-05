package option

// JumaoOutboundOptions is the configuration contract of the 橘猫 (Jumao)
// outbound: stock shadowsocks aes-256-cfb, except the first IV is a watermark
// built from user_id/user_pass. The provider issues ip/port/passwd/user_id/
// user_pass per node and rotates them every 30 minutes, so every field is
// required and a node without a credential cannot be dialled.
type JumaoOutboundOptions struct {
	DialerOptions
	ServerOptions
	// Name is the provider node label, kept as-is.
	Name string `json:"name,omitempty"`
	// Password is the shadowsocks master password (EVP_BytesToKey input).
	Password string `json:"password"`
	// UserID and UserPass form the watermark credential, not the account login.
	UserID   uint32 `json:"user_id"`
	UserPass string `json:"user_pass"`
	// UDP is kept for schema compatibility; UDP framing is not implemented, so
	// UDP traffic is rejected instead of being silently dropped.
	UDP bool `json:"udp,omitempty"`
	// Network lists the supported networks, defaults to ["tcp"].
	Network NetworkList `json:"network,omitempty"`
}
