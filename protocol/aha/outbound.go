package aha

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/aha"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RegisterOutbound only supplies a migration error for old configurations.
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AHAOutboundOptions](registry, C.TypeAHA, NewOutbound)
}
func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, o option.AHAOutboundOptions) (adapter.Outbound, error) {
	return newTunnel(ctx, logger, tag, o)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	options   option.AHAOutboundOptions
	discovery T.Discovery
	dialer    N.Dialer
}

func newTunnel(ctx context.Context, logger log.ContextLogger, tag string, o option.AHAEndpointOptions) (*Outbound, error) {
	if o.Username == "" || o.Password == "" {
		return nil, fmt.Errorf("aha[%s]: username and password are required", tag)
	}
	discovery := T.DiscoveryFromContext(ctx)
	d, err := dialer.New(ctx, o.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	if discovery == nil {
		discovery = &T.HubDiscovery{Dialer: d}
	}
	return &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeAHA, tag, []string{N.NetworkTCP}, o.DialerOptions), ctx: ctx, logger: logger, options: o, discovery: discovery, dialer: d}, nil
}

// DialTunnel discovers account-specific credentials and opens the raw IPv4
// data plane. Never return this directly as an application TCP stream.
func (h *Outbound) dialTunnel(ctx context.Context) (net.Conn, T.Endpoint, error) {
	endpoint, err := h.discovery.Discover(ctx, h.options.Username, h.options.Password, h.options.Region)
	if err != nil {
		return nil, T.Endpoint{}, fmt.Errorf("aha: account discovery failed: %w", err)
	}
	if err = endpoint.Handshake.Validate(); err != nil {
		return nil, T.Endpoint{}, err
	}
	if endpoint.Backend == "" {
		endpoint.Backend = T.BackendHost(endpoint.Handshake.Host)
	}
	if endpoint.Port == 0 {
		endpoint.Port = 443
	}
	tlsOptions := option.OutboundTLSOptions{Enabled: true}
	if h.options.TLS != nil {
		tlsOptions = *h.options.TLS
	}
	if !tlsOptions.Enabled || tlsOptions.DisableSNI || (tlsOptions.ServerName != "" && tlsOptions.ServerName != endpoint.Handshake.Host) {
		return nil, T.Endpoint{}, fmt.Errorf("aha: requires TLS SNI matching discovered camouflage host")
	}
	for _, alpn := range tlsOptions.ALPN {
		if alpn != "http/1.1" {
			return nil, T.Endpoint{}, fmt.Errorf("aha: only HTTP/1.1 ALPN is supported")
		}
	}
	tlsOptions.ServerName = endpoint.Handshake.Host
	config, err := tls.NewClient(h.ctx, h.logger, endpoint.Handshake.Host, tlsOptions)
	if err != nil {
		return nil, T.Endpoint{}, err
	}
	raw, err := h.dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(endpoint.Backend, endpoint.Port))
	if err != nil {
		return nil, T.Endpoint{}, err
	}
	conn, err := T.Handshake(ctx, raw, config, endpoint.Handshake)
	return conn, endpoint, err
}

func (*Outbound) DialContext(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, fmt.Errorf("aha: UDP is not implemented")
	}
	return nil, fmt.Errorf("aha: TCP-to-IPv4 bridge is not implemented; raw L3 tunnel is available through DialTunnel")
}
func (*Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("aha: UDP/ListenPacket is not implemented")
}
