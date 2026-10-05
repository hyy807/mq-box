package aha

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

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

const (
	ahaReconnectInitialBackoff = time.Second
	ahaReconnectMaxBackoff     = 15 * time.Second
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
	ctx      context.Context
	router   adapter.Router
	logger   log.ContextLogger
	dns      adapter.DNSRouter
	tunnel   *Outbound
	device   device.Device
	address  netip.Addr
	ready    atomic.Bool
	closed   atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	conn     net.Conn
	framer   *T.Framer
	done     chan struct{}
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
	e.stop = make(chan struct{})
	e.storeConn(conn)
	e.done = make(chan struct{})
	scope.Add(func() error { return e.shutdown() })
	e.address = netip.MustParseAddr(discovered.Handshake.TunnelIP)
	options := device.Options{Context: scope.Context(), Logger: e.logger, Handler: e, MTU: 1500, UDPTimeout: C.UDPTimeout, ICMPTimeout: C.ICMPTimeout, Configuration: e.configuration(e.address)}
	if manager := service.FromContext[adapter.NetworkManager](e.ctx); manager != nil {
		options.InterfaceFinder = manager.InterfaceFinder()
	}
	d, err := device.New(options)
	if err != nil {
		e.shutdown()
		return err
	}
	e.device = d
	d.SetPacketWriter(e.writeBuffers)
	if err = d.Start(); err != nil {
		d.Close()
		e.shutdown()
		return err
	}
	scope.Add(func() error { e.shutdown(); <-e.done; return d.Close() })
	e.ready.Store(true)
	go e.readLoop()
	return nil
}

func (e *Endpoint) configuration(address netip.Addr) device.Configuration {
	return device.Configuration{MTU: 1500, Address: []netip.Prefix{netip.PrefixFrom(address, 32)}, BlockIPv6: true}
}

func (e *Endpoint) storeConn(conn net.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn = conn
	e.framer = &T.Framer{Reader: conn, Writer: conn}
}

func (e *Endpoint) currentFramer() *T.Framer {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.framer
}

func (e *Endpoint) closeConn() {
	e.mu.Lock()
	conn := e.conn
	e.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// shutdown stops reconnection and releases the socket; it is idempotent because
// both the service scope and the reader can reach it.
func (e *Endpoint) shutdown() error {
	e.closed.Store(true)
	e.ready.Store(false)
	e.stopOnce.Do(func() {
		if e.stop != nil {
			close(e.stop)
		}
	})
	e.closeConn()
	return nil
}

func (e *Endpoint) readLoop() {
	defer close(e.done)
	for {
		packet, err := e.currentFramer().ReadPacket()
		if err != nil {
			if e.closed.Load() {
				return
			}
			// A dropped tunnel must not leave the endpoint permanently unusable: the
			// account's session ends, the server closes, and the next start is a new one.
			e.logger.Debug("aha: tunnel finished: ", err)
			if !e.reconnect() {
				return
			}
			continue
		}
		b := buf.As(packet)
		err = e.device.WriteInboundBuffers([]*buf.Buffer{b})
		b.Release()
		if err != nil {
			return
		}
	}
}

// reconnect re-establishes the data plane until shutdown, using a fresh handshake
// (and a fresh tunnel address when the previous one is no longer offered).
func (e *Endpoint) reconnect() bool {
	e.ready.Store(false)
	e.closeConn()
	backoff := ahaReconnectInitialBackoff
	for {
		select {
		case <-e.stop:
			return false
		case <-e.ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if e.closed.Load() {
			return false
		}
		conn, discovered, err := e.tunnel.dialTunnel(e.ctx)
		if err != nil {
			e.logger.Warn("aha: reconnecting: ", err)
			if backoff < ahaReconnectMaxBackoff {
				backoff *= 2
			}
			continue
		}
		e.storeConn(conn)
		address := netip.MustParseAddr(discovered.Handshake.TunnelIP)
		if address != e.address {
			e.address = address
			if e.device != nil {
				if err = e.device.UpdateConfiguration(e.configuration(address)); err != nil {
					e.logger.Warn("aha: updating the tunnel address failed: ", err)
				}
			}
		}
		e.ready.Store(true)
		e.logger.Info("aha: tunnel re-established")
		return true
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
	framer := e.currentFramer()
	// Framer serializes packets across flow and Go-stack writers.
	for _, packet := range packets {
		if err := framer.WritePacket(packet); err != nil {
			e.ready.Store(false)
			// Closing makes the reader fail and take over with a reconnect.
			e.closeConn()
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
			// A fake address only means something to this client's own router; the peer
			// NATs real addresses, so it must never be carried into the tunnel.
			if address.Is4() && !isFakeAddress(address) {
				return M.SocksaddrFrom(address, destination.Port), nil
			}
		}
		return M.Socksaddr{}, fmt.Errorf("aha: no routable IPv4 destination")
	}
	if !destination.IsIPv4() {
		return M.Socksaddr{}, fmt.Errorf("aha: only IPv4 is supported")
	}
	if isFakeAddress(destination.Addr) {
		return M.Socksaddr{}, fmt.Errorf("aha: refusing to tunnel a fake address")
	}
	return destination, nil
}

// isFakeAddress reports whether the address belongs to the standard fake-IP pools.
func isFakeAddress(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	bytes := address.As4()
	return bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if e.device == nil {
		return nil, fmt.Errorf("aha: device not started")
	}
	resolved, err := e.ipv4Destination(ctx, destination)
	if err != nil {
		return nil, err
	}
	return e.device.DialContext(ctx, network, resolved)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if e.device == nil {
		return nil, fmt.Errorf("aha: device not started")
	}
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
