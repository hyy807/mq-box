// Package vlessxhttp is VLESS carried over the XHTTP (HTTP/2) transport. It
// uses the sing-vmess VLESS client library and the private XHTTP transport;
// upstream protocol/vless and transport/v2ray are not modified.
package vlessxhttp

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	MC "github.com/sagernet/sing-box/mods/modconst"
	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/mods/modtls"
	"github.com/sagernet/sing-box/mods/transport/v2rayxhttp"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.VLESSXHTTPOutboundOptions](registry, MC.TypeVLESSXHTTP, NewOutbound)
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	client     *vless.Client
	transport  *v2rayxhttp.Client
	packetAddr bool
	xudp       bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.VLESSXHTTPOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("vless-xhttp requires TLS")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := modtls.NewClient(ctx, logger, options.Server, options.TLS)
	if err != nil {
		return nil, err
	}
	transport, err := v2rayxhttp.NewClient(outboundDialer, options.ServerOptions.Build(), options.XHTTP, tlsConfig)
	if err != nil {
		return nil, E.Cause(err, "create xhttp transport")
	}
	h := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(MC.TypeVLESSXHTTP, tag, options.Network.Build(), options.DialerOptions),
		logger:    logger,
		transport: transport,
	}
	if options.PacketEncoding == nil {
		h.xudp = true
	} else {
		switch *options.PacketEncoding {
		case "":
		case "packetaddr":
			h.packetAddr = true
		case "xudp":
			h.xudp = true
		default:
			return nil, E.New("unknown packet encoding: ", *options.PacketEncoding)
		}
	}
	h.client, err = vless.NewClient(options.UUID, "", logger)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(h.transport.Close)
	}
	return nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.transport.Close()
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := h.transport.DialContext(ctx)
		if err != nil {
			return nil, err
		}
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.listenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.listenPacket(ctx, destination)
}

func (h *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.transport.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	} else if h.packetAddr {
		if destination.IsDomain() {
			conn.Close()
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		packetConn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(packetConn, destination), nil
	}
	return h.client.DialEarlyPacketConn(conn, destination)
}
