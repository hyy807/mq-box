package option

import "github.com/sagernet/sing/common/json/badoption"

type ShadowQUICOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username             string             `json:"username"`
	Password             string             `json:"password"`
	SNI                  string             `json:"sni,omitempty"`
	ALPN                 []string           `json:"alpn,omitempty"`
	QUICVersions         []string           `json:"quic_versions,omitempty"`
	UDPOverStream        bool               `json:"udp_over_stream,omitempty"`
	ZeroRTT              bool               `json:"zero_rtt,omitempty"`
	KeepAliveInterval    int                `json:"keep_alive_interval,omitempty"`
	ReceiveWindowConn    uint64             `json:"recv_window_conn,omitempty"`
	ReceiveWindow        uint64             `json:"recv_window,omitempty"`
	DisableMTUDiscovery  bool               `json:"disable_mtu_discovery,omitempty"`
	MaxDatagramFrameSize int64              `json:"max_datagram_frame_size,omitempty"`
	MaxOpenStreams       int64              `json:"max_open_streams,omitempty"`
	CongestionController string             `json:"congestion_controller,omitempty"`
	Up                   string             `json:"up,omitempty"`
	Down                 string             `json:"down,omitempty"`
	CWND                 int                `json:"cwnd,omitempty"`
	BBRProfile           string             `json:"bbr_profile,omitempty"`
	Network              NetworkList        `json:"network,omitempty"`
	KeepAlivePeriod      badoption.Duration `json:"keep_alive_period,omitempty"`
}
