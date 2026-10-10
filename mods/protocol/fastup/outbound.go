// Package fastup is the FastUP outbound: the Trojan wire protocol whose key is
// derived from password + mpw. It reuses the upstream trojan wire codec
// (transport/trojan) read-only; upstream protocol/trojan is not modified.
package fastup

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	stls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	MC "github.com/sagernet/sing-box/mods/modconst"
	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/mods/modtls"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.FastUPOutboundOptions](registry, MC.TypeFastUP, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

// DerivePassword returns hex(md5(password + mpw)); with an empty mpw the
// password is returned unchanged (plain Trojan).
func DerivePassword(password string, mpw string) string {
	if mpw == "" {
		return password
	}
	digest := md5.Sum([]byte(password + mpw))
	return hex.EncodeToString(digest[:])
}

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	serverAddr      M.Socksaddr
	key             [56]byte
	multiplexDialer *mux.Client
	tlsConfig       stls.Config
	tlsDialer       stls.Dialer
	transport       adapter.V2RayClientTransport
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.FastUPOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	h := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(MC.TypeFastUP, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		key:        trojan.Key(DerivePassword(options.Password, options.Mpw)),
	}
	h.tlsConfig, err = modtls.NewClient(ctx, logger, options.Server, options.TLS)
	if err != nil {
		return nil, err
	}
	if h.tlsConfig != nil {
		h.tlsDialer = stls.NewDialer(outboundDialer, h.tlsConfig)
	}
	if options.Transport != nil {
		h.transport, err = v2ray.NewClientTransport(ctx, h.dialer, h.serverAddr, common.PtrValueOrDefault(options.Transport), h.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	h.multiplexDialer, err = mux.NewClientWithOptions((*fastupDialer)(h), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound ", network, " connection to ", destination)
		return (*fastupDialer)(h).DialContext(ctx, network, destination)
	}
	h.logger.InfoContext(ctx, "outbound multiplex ", network, " connection to ", destination)
	return h.multiplexDialer.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*fastupDialer)(h).ListenPacket(ctx, destination)
	}
	h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
	return h.multiplexDialer.ListenPacket(ctx, destination)
}

func (h *Outbound) MultiplexEnabled() bool {
	if h.multiplexDialer != nil {
		return true
	}
	t, ok := h.transport.(adapter.V2RayMultiplexClientTransport)
	return ok && t.MultiplexEnabled()
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if k, ok := h.transport.(adapter.IdleConnectionKeeper); ok {
		k.SetKeepIdleConnections(keep)
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	if k, ok := h.transport.(adapter.IdleConnectionKeeper); ok {
		k.CloseIdleConnections()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.CloseIdleConnections()
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.transport != nil {
		scope.Add(h.transport.Close)
	}
	if h.multiplexDialer != nil {
		scope.Add(h.multiplexDialer.Close)
	}
	return nil
}

type fastupDialer Outbound

func (h *fastupDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return trojan.NewClientConn(conn, h.key, destination), nil
	case N.NetworkUDP:
		return bufio.NewBindPacketConn(trojan.NewClientPacketConn(conn, h.key), destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *fastupDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return conn.(net.PacketConn), nil
}
