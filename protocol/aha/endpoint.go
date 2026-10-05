package aha

import (
	"context"
	"fmt"
	"math"
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
	// How long a flow waits for the tunnel to come up on demand.
	ahaConnectWait = 10 * time.Second
	// A data plane is a complete Go IP stack, so a node list is cheap only while
	// the nodes are unused: the stack is built when a flow first needs the node and
	// dropped again once the node has been idle. Without this, a 195 node list costs
	// ~18 MB of the NetworkExtension budget before a single byte is proxied.
	ahaMaxIdleDataPlanes = 3
	ahaMaxLiveDataPlanes = 6
	ahaIdleDataPlaneAge  = 30 * time.Second
)

// A latency test of a whole node list runs every member at once; each probe holds a
// TLS session, so the concurrency is bounded to keep the peak inside the extension
// budget while still finishing a 200 node list in a few seconds.
const ahaMaxConcurrentProbes = 48

var ahaProbeSlots = make(chan struct{}, ahaMaxConcurrentProbes)

// liveDataPlanes tracks the endpoints of this process that currently hold a data
// plane, oldest first, so a node burst cannot keep one IP stack per node alive.
var liveDataPlanes struct {
	mu   sync.Mutex
	list []*Endpoint
}

func registerLiveDataPlane(e *Endpoint) {
	liveDataPlanes.mu.Lock()
	defer liveDataPlanes.mu.Unlock()
	kept := make([]*Endpoint, 0, len(liveDataPlanes.list)+1)
	for _, other := range liveDataPlanes.list {
		if other != e && !other.closed.Load() {
			kept = append(kept, other)
		}
	}
	kept = append(kept, e)
	liveDataPlanes.list = kept
	now := time.Now().UnixNano()
	var evict []*Endpoint
	live := len(kept)
	for _, other := range kept[:len(kept)-1] {
		if live <= ahaMaxIdleDataPlanes {
			break
		}
		idle := now-other.lastUsed.Load() > int64(ahaIdleDataPlaneAge)
		if idle || live > ahaMaxLiveDataPlanes {
			evict = append(evict, other)
			live--
		}
	}
	if len(evict) > 0 {
		liveDataPlanes.list = kept[len(evict):]
	}
	go func() {
		for _, victim := range evict {
			if victim.logger != nil {
				victim.logger.Debug("aha: releasing the idle data plane")
			}
			victim.releaseDataPlane()
		}
	}()
}

func unregisterLiveDataPlane(e *Endpoint) {
	liveDataPlanes.mu.Lock()
	defer liveDataPlanes.mu.Unlock()
	kept := liveDataPlanes.list[:0]
	for _, other := range liveDataPlanes.list {
		if other != e {
			kept = append(kept, other)
		}
	}
	liveDataPlanes.list = kept
}

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.AHAEndpointOptions](registry, C.TypeAHA, NewEndpoint)
}

var (
	_ adapter.Endpoint                = (*Endpoint)(nil)
	_ adapter.FlowOutbound            = (*Endpoint)(nil)
	_ adapter.OutboundWithLatencyTest = (*Endpoint)(nil)
	_ tun.Handler                     = (*Endpoint)(nil)
)

// Endpoint connects the core's Go IP stack and native TUN flow return path to
// the raw IPv4 TLS stream. Application TCP/UDP bytes never enter TLS directly.
//
// The tunnel is opened on demand rather than at startup: a selector normally
// uses one node, so dialling every configured endpoint would hold a session per
// region, flood the account's login API and make the whole service fail whenever
// one node is unavailable.
type Endpoint struct {
	endpoint.Adapter
	ctx      context.Context
	router   adapter.Router
	logger   log.ContextLogger
	dns      adapter.DNSRouter
	tunnel   *Outbound
	device   device.Device
	deviceMu sync.Mutex
	// deviceCtx is the service scope, kept because the data plane may be built long
	// after Start.
	deviceCtx context.Context
	address   netip.Addr
	ready     atomic.Bool
	closed    atomic.Bool
	stop      chan struct{}
	stopOnce  sync.Once
	mu        sync.Mutex
	conn      net.Conn
	framer    *T.Framer
	done      chan struct{}

	// lastUsed is the last time this node carried a packet, used to decide which
	// data plane to release first.
	lastUsed atomic.Int64

	readerStarted atomic.Bool
	connectMu     sync.Mutex
	connecting    chan struct{}
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AHAEndpointOptions) (adapter.Endpoint, error) {
	credentials, err := T.ResolveCredentials(ctx, options.Account, options.Username, options.Password)
	if err != nil {
		return nil, err
	}
	options.Account = ""
	options.Username, options.Password = credentials.Username, credentials.Password
	tunnel, err := newTunnel(ctx, logger, tag, options)
	// The router may fetch its rule sets through this endpoint before Start runs
	// (an initial rule-set download goes through the default HTTP client), so the
	// address and the scope context are seeded here as well.
	return &Endpoint{
		Adapter:   endpoint.NewAdapterWithDialerOptions(C.TypeAHA, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:       ctx,
		router:    router,
		logger:    logger,
		dns:       service.FromContext[adapter.DNSRouter](ctx),
		tunnel:    tunnel,
		deviceCtx: ctx,
		address:   netip.MustParseAddr(T.RandomTunnelAddress()),
	}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	e.stop = make(chan struct{})
	e.done = make(chan struct{})
	e.deviceCtx = scope.Context()
	e.lastUsed.Store(time.Now().UnixNano())
	scope.Add(func() error { return e.shutdown() })
	// The address is chosen up front and offered during the handshake, so the TUN
	// address the peer NATs to is known before the first connection exists.
	e.address = netip.MustParseAddr(T.RandomTunnelAddress())
	e.tunnel.preferredAddress = e.address.String()
	// The data plane is deliberately not built here: a node list only has to be
	// cheap, and a node that is never used must not hold an IP stack.
	return nil
}

// ensureDataPlane builds the Go IP stack of this node on first use.
func (e *Endpoint) ensureDataPlane() (device.Device, error) {
	e.deviceMu.Lock()
	defer e.deviceMu.Unlock()
	if e.device != nil {
		return e.device, nil
	}
	if e.closed.Load() {
		return nil, fmt.Errorf("aha: endpoint is closed")
	}
	options := device.Options{Context: e.deviceCtx, Logger: e.logger, Handler: e, MTU: 1500, UDPTimeout: C.UDPTimeout, ICMPTimeout: C.ICMPTimeout, Configuration: e.configuration(e.address)}
	if manager := service.FromContext[adapter.NetworkManager](e.ctx); manager != nil {
		options.InterfaceFinder = manager.InterfaceFinder()
	}
	d, err := device.New(options)
	if err != nil {
		return nil, err
	}
	d.SetPacketWriter(e.writeBuffers)
	if err = d.Start(); err != nil {
		d.Close()
		return nil, err
	}
	e.device = d
	e.lastUsed.Store(time.Now().UnixNano())
	registerLiveDataPlane(e)
	return d, nil
}

// releaseDataPlane drops the data plane of an idle node; the next flow rebuilds it.
func (e *Endpoint) releaseDataPlane() {
	e.deviceMu.Lock()
	d := e.device
	e.device = nil
	e.deviceMu.Unlock()
	if d == nil {
		return
	}
	e.ready.Store(false)
	e.closeConn()
	_ = d.Close()
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

// shutdown stops reconnection and releases the socket and the data plane; it is
// idempotent because both the service scope and the reader can reach it.
func (e *Endpoint) shutdown() error {
	e.closed.Store(true)
	e.ready.Store(false)
	e.stopOnce.Do(func() {
		if e.stop != nil {
			close(e.stop)
		}
	})
	e.closeConn()
	if e.readerStarted.Load() {
		select {
		case <-e.done:
		case <-time.After(2 * time.Second):
		}
	}
	unregisterLiveDataPlane(e)
	e.deviceMu.Lock()
	d := e.device
	e.device = nil
	e.deviceMu.Unlock()
	if d != nil {
		_ = d.Close()
	}
	return nil
}

// connectAsync opens the tunnel once, regardless of how many flows ask for it.
func (e *Endpoint) connectAsync() {
	e.connectMu.Lock()
	if e.connecting != nil {
		e.connectMu.Unlock()
		return
	}
	wait := make(chan struct{})
	e.connecting = wait
	e.connectMu.Unlock()
	go func() {
		defer close(wait)
		if _, _, err := e.connect(); err != nil {
			e.logger.Debug("aha: connecting the tunnel failed: ", err)
		}
		e.connectMu.Lock()
		e.connecting = nil
		e.connectMu.Unlock()
	}()
}

func (e *Endpoint) ensureConnected(ctx context.Context) error {
	if e.ready.Load() {
		return nil
	}
	if e.closed.Load() {
		return fmt.Errorf("aha: endpoint is closed")
	}
	e.connectAsync()
	e.connectMu.Lock()
	wait := e.connecting
	e.connectMu.Unlock()
	if wait != nil {
		waitCtx, cancel := context.WithTimeout(ctx, ahaConnectWait)
		defer cancel()
		select {
		case <-wait:
		case <-waitCtx.Done():
		case <-e.stop:
			return fmt.Errorf("aha: endpoint is closed")
		}
	}
	if e.ready.Load() {
		return nil
	}
	return fmt.Errorf("aha: endpoint is not connected")
}

// connect performs one handshake and adopts the address the peer accepted.
func (e *Endpoint) connect() (net.Conn, T.Endpoint, error) {
	if e.closed.Load() {
		return nil, T.Endpoint{}, fmt.Errorf("aha: endpoint is closed")
	}
	conn, discovered, err := e.tunnel.dialTunnel(e.ctx)
	if err != nil {
		return nil, T.Endpoint{}, err
	}
	address := netip.MustParseAddr(discovered.Handshake.TunnelIP)
	e.storeConn(conn)
	var dataPlane device.Device
	dataPlane, err = e.ensureDataPlane()
	if err != nil {
		e.closeConn()
		return nil, T.Endpoint{}, err
	}
	if address != e.address {
		e.address = address
		if err = dataPlane.UpdateConfiguration(e.configuration(address)); err != nil {
			e.logger.Warn("aha: updating the tunnel address failed: ", err)
		}
	}
	e.tunnel.preferredAddress = address.String()
	e.ready.Store(true)
	e.lastUsed.Store(time.Now().UnixNano())
	if e.readerStarted.CompareAndSwap(false, true) {
		go e.readLoop()
	}
	return conn, discovered, nil
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
		e.deviceMu.Lock()
		d := e.device
		e.deviceMu.Unlock()
		if d == nil {
			// Only flows this endpoint dialled can return traffic, so this is a
			// leftover packet after the data plane was released.
			b.Release()
			continue
		}
		e.lastUsed.Store(time.Now().UnixNano())
		err = d.WriteInboundBuffers([]*buf.Buffer{b})
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
		if _, _, err := e.connect(); err != nil {
			e.logger.Warn("aha: reconnecting: ", err)
			if backoff < ahaReconnectMaxBackoff {
				backoff *= 2
			}
			continue
		}
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
		// The read side is what opens the tunnel, so a first inbound packet both
		// reports the transient state and starts the connection.
		e.connectAsync()
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
	e.deviceMu.Lock()
	d := e.device
	e.deviceMu.Unlock()
	if d == nil {
		// The address is offered during the handshake before any data plane exists,
		// so the flow dispatcher already knows this node's own address space.
		return e.address, netip.Addr{}
	}
	return d.PortAddresses()
}

func (e *Endpoint) PortMTU() uint32 { return 1500 }

func (e *Endpoint) AttachReturn(r tun.Return) error {
	d, err := e.ensureDataPlane()
	if err != nil {
		return err
	}
	return d.AttachReturn(r)
}

func (e *Endpoint) DetachReturn(r tun.Return) error {
	e.deviceMu.Lock()
	d := e.device
	e.deviceMu.Unlock()
	if d == nil {
		return nil
	}
	return d.DetachReturn(r)
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
	if err := e.ensureConnected(ctx); err != nil {
		return nil, err
	}
	resolved, err := e.ipv4Destination(ctx, destination)
	if err != nil {
		return nil, err
	}
	dataPlane, err := e.ensureDataPlane()
	if err != nil {
		return nil, err
	}
	e.lastUsed.Store(time.Now().UnixNano())
	conn, err := dataPlane.DialContext(ctx, network, resolved)
	return conn, err
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := e.ensureConnected(ctx); err != nil {
		return nil, err
	}
	resolved, err := e.ipv4Destination(ctx, destination)
	if err != nil {
		return nil, err
	}
	dataPlane, err := e.ensureDataPlane()
	if err != nil {
		return nil, err
	}
	e.lastUsed.Store(time.Now().UnixNano())
	conn, err := dataPlane.ListenPacket(ctx, resolved)
	if err != nil {
		return nil, err
	}
	// Keep the original domain destination usable by ordinary UDP routing.
	return &packetConn{PacketConn: conn, original: destination, resolved: resolved}, nil
}

// TestLatency answers a node latency test with the round-trip time of a probe
// carried by the node's own tunnel. It opens no data plane: a latency test of a
// whole node list would otherwise build one Go IP stack per node, which is what
// pushes the iOS extension into memory pressure.
func (e *Endpoint) TestLatency(ctx context.Context) (uint16, error) {
	select {
	case ahaProbeSlots <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-ahaProbeSlots }()
	start := time.Now()
	conn, discovered, err := e.tunnel.dialTunnelForProbe(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err = T.ProbeTunnel(ctx, conn, discovered.Handshake.TunnelIP); err != nil {
		return 0, err
	}
	delay := time.Since(start)
	if delay > math.MaxUint16*time.Millisecond {
		delay = math.MaxUint16 * time.Millisecond
	}
	e.lastUsed.Store(time.Now().UnixNano())
	return uint16(delay.Milliseconds()), nil
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
