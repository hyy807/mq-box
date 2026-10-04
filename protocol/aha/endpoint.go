package aha

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/aha"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.AHAEndpointOptions](registry, C.TypeAHA, NewEndpoint)
}

var (
	_ adapter.Endpoint     = (*Endpoint)(nil)
	_ adapter.FlowOutbound = (*Endpoint)(nil)
	_ tun.Handler          = (*Endpoint)(nil)
)

// Endpoint connects the core's Go IP stack and native TUN flow return path to
// the raw IPv4 TLS stream. Application TCP/UDP bytes never enter TLS directly.
type Endpoint struct {
	endpoint.Adapter
	ctx    context.Context
	router adapter.Router
	logger log.ContextLogger
	dns    adapter.DNSRouter
	tunnel *Outbound
	device device.Device
	conn   net.Conn
	framer *T.Framer
	ready  atomic.Bool
	done   chan struct{}
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AHAEndpointOptions) (adapter.Endpoint, error) {
	credentials, err := T.ResolveCredentials(ctx, options.Account, options.Username, options.Password)
	if err != nil {
		return nil, err
	}
	options.Account = ""
	options.Username, options.Password = credentials.Username, credentials.Password
	tunnel, err := newTunnel(ctx, logger, tag, options)
	if err != nil {
		return nil, err
	}
	return &Endpoint{Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeAHA, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions), ctx: ctx, router: router, logger: logger, dns: service.FromContext[adapter.DNSRouter](ctx), tunnel: tunnel}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	conn, discovered, err := e.tunnel.dialTunnel(scope.Context())
	if err != nil {
		return err
	}
	e.conn = conn
	e.framer = &T.Framer{Reader: conn, Writer: conn}
	// Close the connection before waiting for the reader during scope cleanup.
	e.done = make(chan struct{})
	scope.Add(func() error { <-e.done; return nil })
	scope.Add(func() error { e.ready.Store(false); return conn.Close() })
	address := netip.MustParseAddr(discovered.Handshake.TunnelIP)
	options := device.Options{Context: scope.Context(), Logger: e.logger, Handler: e, MTU: 1500, UDPTimeout: C.UDPTimeout, ICMPTimeout: C.ICMPTimeout, Configuration: device.Configuration{MTU: 1500, Address: []netip.Prefix{netip.PrefixFrom(address, 32)}, BlockIPv6: true}}
	if manager := service.FromContext[adapter.NetworkManager](e.ctx); manager != nil {
		options.InterfaceFinder = manager.InterfaceFinder()
	}
	d, err := device.New(options)
	if err != nil {
		close(e.done)
		return err
	}
	e.device = d
	d.SetPacketWriter(e.writeBuffers)
	if err = d.Start(); err != nil {
		d.Close()
		close(e.done)
		return err
	}
	// Device closes after the reader stops, not while it is delivering packets.
	// This cleanup is registered first in a child scope to retain LIFO ordering.
	scope.Add(func() error { e.ready.Store(false); conn.Close(); <-e.done; return d.Close() })
	e.ready.Store(true)
	go e.readLoop()
	return nil
}

func (e *Endpoint) readLoop() {
	defer close(e.done)
	defer e.ready.Store(false)
	defer e.conn.Close()
	for {
		packet, err := e.framer.ReadPacket()
		if err != nil {
			return
		}
		b := buf.As(packet)
		err = e.device.WriteInboundBuffers([]*buf.Buffer{b})
		b.Release()
		if err != nil {
			return
		}
	}
}
func (e *Endpoint) writeBuffers(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	packets := make([][]byte, len(buffers))
	for i, b := range buffers {
		packets[i] = b.Bytes()
	}
	return e.WritePackets(packets)
}
func (e *Endpoint) WritePackets(packets [][]byte) error {
	if !e.ready.Load() {
		return fmt.Errorf("aha: endpoint is not connected")
	}
	// Framer serializes packets across flow and Go-stack writers.
	for _, packet := range packets {
		if err := e.framer.WritePacket(packet); err != nil {
			e.ready.Store(false)
			e.conn.Close()
			return err
		}
	}
	return nil
}
func (e *Endpoint) PreMatchFlow(_ string, destination netip.Addr) adapter.PreMatchAction {
	if destination.Is6() {
		return adapter.PreMatchReject
	}
	return adapter.PreMatchFlow
}
func (e *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	if e.device == nil {
		return netip.Addr{}, netip.Addr{}
	}
	return e.device.PortAddresses()
}
func (e *Endpoint) PortMTU() uint32 { return 1500 }
func (e *Endpoint) AttachReturn(r tun.Return) error {
	if e.device == nil {
		return fmt.Errorf("aha: device not started")
	}
	return e.device.AttachReturn(r)
}
func (e *Endpoint) DetachReturn(r tun.Return) error {
	if e.device == nil {
		return nil
	}
	return e.device.DetachReturn(r)
}
func (e *Endpoint) JudgeFlow(network uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return adapter.JudgeFlow(e.router, adapter.InboundContext{Inbound: e.Tag(), InboundType: e.Type()}, network, source, destination, firstPacket)
}
func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e.router.RouteConnectionEx(ctx, conn, adapter.InboundContext{Inbound: e.Tag(), InboundType: e.Type(), Source: source, Destination: destination}, onClose)
}
func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e.router.RoutePacketConnectionEx(ctx, conn, adapter.InboundContext{Inbound: e.Tag(), InboundType: e.Type(), Source: source, Destination: destination}, onClose)
}
func (e *Endpoint) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	e.router.HijackDNSPacket(e.ctx, payload, writer, adapter.InboundContext{Inbound: e.Tag(), InboundType: e.Type(), Network: N.NetworkUDP, Source: source, Destination: destination, Protocol: C.ProtocolDNS})
}
func (e *Endpoint) ipv4Destination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if !e.ready.Load() {
		return M.Socksaddr{}, fmt.Errorf("aha: endpoint is not connected")
	}
	if destination.IsDomain() {
		if e.dns == nil {
			return M.Socksaddr{}, fmt.Errorf("aha: DNS router unavailable")
		}
		addresses, err := e.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return M.Socksaddr{}, err
		}
		for _, address := range addresses {
			if address.Is4() {
				return M.SocksaddrFrom(address, destination.Port), nil
			}
		}
		return M.Socksaddr{}, fmt.Errorf("aha: no IPv4 destination")
	}
	if !destination.IsIPv4() {
		return M.Socksaddr{}, fmt.Errorf("aha: only IPv4 is supported")
	}
	return destination, nil
}
func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	resolved, err := e.ipv4Destination(ctx, destination)
	if err != nil {
		return nil, err
	}
	return e.device.DialContext(ctx, network, resolved)
}
func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	resolved, err := e.ipv4Destination(ctx, destination)
	if err != nil {
		return nil, err
	}
	conn, err := e.device.ListenPacket(ctx, resolved)
	if err != nil {
		return nil, err
	}
	// Keep the original domain destination usable by ordinary UDP routing.
	return &packetConn{PacketConn: conn, original: destination, resolved: resolved}, nil
}

type packetConn struct {
	net.PacketConn
	original, resolved M.Socksaddr
	once               sync.Once
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if destination == c.original {
		destination = c.resolved
	}
	if !destination.IsIPv4() {
		return 0, fmt.Errorf("aha: only IPv4 is supported")
	}
	return c.PacketConn.WriteTo(p, destination.UDPAddr())
}
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && M.SocksaddrFromNet(addr) == c.resolved {
		return n, c.original, nil
	}
	return n, addr, err
}
