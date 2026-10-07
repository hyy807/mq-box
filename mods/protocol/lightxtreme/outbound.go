// Package lightxtreme is the LightXtreme outbound: AnyTLS framing (from the
// sing-anytls library) with the LightXtreme private authentication. It is an
// independent implementation; upstream protocol/anytls is not modified.
package lightxtreme

import (
	"context"
	"net"
	"os"

	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	stls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	MC "github.com/sagernet/sing-box/mods/modconst"
	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/mods/modtls"
	T "github.com/sagernet/sing-box/mods/transport/lightxtreme"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.LightXtremeOutboundOptions](registry, MC.TypeLightXtreme, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	dialer        stls.Dialer
	server        M.Socksaddr
	clientOptions anytls.ClientOptions
	client        *anytls.Client
	uotClient     *uot.Client
	logger        log.ContextLogger
	auth          [32]byte
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.LightXtremeOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.DialerOptions.TCPFastOpen {
		return nil, E.New("tcp_fast_open is not supported with lightxtreme outbound")
	}
	tlsConfig, err := modtls.NewClient(ctx, logger, options.Server, options.TLS)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}
	marker := options.PlatformMarker
	if marker == 0 {
		marker = T.DefaultPlatformMarker
	}
	h := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(MC.TypeLightXtreme, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		dialer:  stls.NewDialer(outboundDialer, tlsConfig),
		server:  options.ServerOptions.Build(),
		logger:  logger,
		auth:    T.Auth(options.Password, marker),
	}
	h.clientOptions = anytls.ClientOptions{
		Password:                 options.Password,
		ClientMetadata:           options.ClientMetadata,
		DialOut:                  h.dialOut,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		Logger:                   logger,
	}
	return h, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	client, err := anytls.NewClient(h.clientOptions)
	if err != nil {
		return err
	}
	h.client = client
	scope.Add(client.Close)
	h.uotClient = &uot.Client{Dialer: streamDialer(client.DialContext), Version: uot.Version}
	return nil
}

type streamDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d streamDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d streamDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	conn, err := h.dialer.DialTLSContext(adapter.ContextForMultiplexSession(ctx), h.server)
	if err != nil {
		return nil, err
	}
	return T.WrapAuth(conn, h.auth), nil
}

func (h *Outbound) MultiplexEnabled() bool               { return true }
func (h *Outbound) InterfaceUpdated(ctx context.Context) { h.client.Reset() }
func (h *Outbound) SetKeepIdleConnections(keep bool)     { h.client.SetKeepIdleConnections(keep) }
func (h *Outbound) CloseIdleConnections()                { h.client.CloseIdleConnections() }

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}
