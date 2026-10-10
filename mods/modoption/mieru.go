package modoption

import (
	"github.com/sagernet/sing-box/option"
)

type MieruOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	PortRange      string             `json:"port_range,omitempty"`
	Transport      string             `json:"transport"`
	Username       string             `json:"username"`
	Password       string             `json:"password"`
	Multiplexing   string             `json:"multiplexing,omitempty"`
	HandshakeMode  string             `json:"handshake_mode,omitempty"`
	TrafficPattern string             `json:"traffic_pattern,omitempty"`
	Network        option.NetworkList `json:"network,omitempty"`
}
