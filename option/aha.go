package option

// AHAEndpointOptions is persisted by the existing JSON profile mechanism.
// Inline username/password work with ordinary profiles. For Keychain-backed
// profiles save only account, and inject transport/aha.CredentialStore at runtime.
// Replacing account and reloading the profile closes the old account's tunnel.
type AHAEndpointOptions struct {
	DialerOptions
	OutboundTLSOptionsContainer
	Account  string `json:"account,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Region   string `json:"region,omitempty"`
	Node     string `json:"node,omitempty"`
}

// AHAOutboundOptions is retained for source compatibility only; AHA is an L3
// endpoint, not an ordinary TCP outbound.
type AHAOutboundOptions = AHAEndpointOptions
