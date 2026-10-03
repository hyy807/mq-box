package oppa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/oppa"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.OppaOutboundOptions](registry, C.TypeOppa, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	password   string
	udp        bool
	tlsConfig  *tls.Config
	pool       *connPool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.OppaOutboundOptions) (adapter.Outbound, error) {
	if err := oppa.ValidatePassword(options.Password); err != nil {
		return nil, E.Cause(err, "oppa[", tag, "]")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	network := options.Network.Build()
	if len(network) == 0 {
		network = []string{N.NetworkTCP}
		if options.UDP {
			network = append(network, N.NetworkUDP)
		}
	}
	instance := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeOppa, tag, network, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		password:   options.Password,
		udp:        common.Contains(network, N.NetworkUDP),
	}
	// Vendor compatible mode: the reference clients set an internal
	// ServerName of localhost with SNI disabled, send no ALPN extension and
	// use a custom verifier that accepts any certificate. An empty ServerName
	// with InsecureSkipVerify produces exactly that ClientHello.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
	if options.TLS != nil {
		tlsOptions := common.PtrValueOrDefault(options.TLS)
		if tlsOptions.ServerName != "" {
			tlsConfig.ServerName = tlsOptions.ServerName
		}
		if tlsOptions.DisableSNI {
			tlsConfig.ServerName = ""
		}
		if len(tlsOptions.ALPN) > 0 {
			tlsConfig.NextProtos = tlsOptions.ALPN
		}
		if !tlsOptions.Insecure {
			if tlsConfig.ServerName == "" {
				tlsConfig.ServerName = options.Server
			}
			roots, rootErr := x509.SystemCertPool()
			if rootErr != nil {
				return nil, E.Cause(rootErr, "load system certificate pool")
			}
			tlsConfig.RootCAs = roots
			tlsConfig.InsecureSkipVerify = false
		}
	}
	instance.tlsConfig = tlsConfig
	instance.pool = newConnPool(instance, options.PreConnect)
	return instance, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.dialRequest(ctx, oppa.CommandTCP, destination)
	case N.NetworkUDP:
		if !h.udp {
			return nil, E.New("oppa: UDP is not enabled for this outbound")
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		channelConn, err := h.dialChannel(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(channelConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !h.udp {
		return nil, E.New("oppa: UDP is not enabled for this outbound")
	}
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.dialChannel(ctx)
}

func (h *Outbound) Close() error {
	return h.pool.Close()
}

// dialRequest writes the stream header AUTH_RAW32 || command || SOCKS_ADDR on a
// warm connection when the pre-connect pool has one. Skipping the TCP handshake
// and the TLS handshake saves two round trips per connection, which is what the
// pre-connect option of the reference client is for.
func (h *Outbound) dialRequest(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, error) {
	h.pool.Touch()
	conn, reused := h.pool.Take()
	if conn == nil {
		var err error
		conn, err = h.dialTLS(ctx)
		if err != nil {
			return nil, err
		}
	}
	err := oppa.WriteRequest(conn, h.password, command, destination)
	if err != nil && reused {
		// A pooled connection may have been closed by the server meanwhile.
		common.Close(conn)
		conn, err = h.dialTLS(ctx)
		if err != nil {
			return nil, err
		}
		err = oppa.WriteRequest(conn, h.password, command, destination)
	}
	if err != nil {
		common.Close(conn)
		return nil, E.Cause(err, "write request")
	}
	return conn, nil
}

// dialChannel opens a connection for the UDP channel: AUTH_RAW32 || 0x02.
func (h *Outbound) dialChannel(ctx context.Context) (*oppa.UDPConn, error) {
	h.pool.Touch()
	conn, _ := h.pool.Take()
	if conn == nil {
		var err error
		conn, err = h.dialTLS(ctx)
		if err != nil {
			return nil, err
		}
	}
	if err := oppa.WriteChannelRequest(conn, h.password); err != nil {
		common.Close(conn)
		return nil, E.Cause(err, "write channel request")
	}
	return oppa.NewUDPConn(conn, channelAddress(conn)), nil
}

func (h *Outbound) dialTLS(ctx context.Context) (net.Conn, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "connect to ", h.serverAddr)
	}
	if deadline, loaded := ctx.Deadline(); loaded {
		_ = rawConn.SetDeadline(deadline)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	tlsConn := tls.Client(rawConn, h.tlsConfig)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		common.Close(rawConn)
		return nil, E.Cause(err, "TLS handshake with ", h.serverAddr)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// channelAddress reports the session socket address used as the channel
// identifier inside UDP frames. The reference implementation takes it from
// session metadata rather than a constant.
func channelAddress(conn net.Conn) M.Socksaddr {
	localAddr := conn.LocalAddr()
	if localAddr == nil {
		return M.Socksaddr{}
	}
	return M.SocksaddrFromNet(localAddr)
}

const (
	// poolIdleTimeout drops warm connections that sat unused for too long.
	poolIdleTimeout = 60 * time.Second
	// poolFillDelay waits for the traffic to settle before buying a warm
	// connection, so a latency sweep over many nodes never fills any pool.
	poolFillDelay = 3 * time.Second
	// poolFillInterval spaces the dials of one fill loop.
	poolFillInterval = 300 * time.Millisecond
	// poolIdleBudget caps the warm connections of the whole process. 180 nodes
	// x pre_connect would otherwise exhaust the 50 MB iOS network extension.
	poolIdleBudget = 32
)

var (
	// Only one outbound keeps idle connections at a time: the one that carried
	// the most recent connection. Switching nodes closes the previous pool.
	activePoolAccess sync.Mutex
	activePool       *connPool
	idleCount        atomic.Int32
)

func setActivePool(pool *connPool) {
	activePoolAccess.Lock()
	previous := activePool
	activePool = pool
	activePoolAccess.Unlock()
	if previous != nil && previous != pool {
		previous.closeIdle()
	}
}

func isActivePool(pool *connPool) bool {
	activePoolAccess.Lock()
	active := activePool == pool
	activePoolAccess.Unlock()
	return active
}

// connPool keeps pre-connect connections warm. It only fills after the
// outbound carried traffic, only while it stays the active outbound and only
// while the process wide idle budget is not exhausted.
type connPool struct {
	access   sync.Mutex
	instance *Outbound
	limit    int
	filling  bool
	closed   bool
	conns    []pooledConn
	timer    *time.Timer
}

type pooledConn struct {
	conn    net.Conn
	created time.Time
}

func newConnPool(instance *Outbound, limit int) *connPool {
	if limit < 0 {
		limit = 0
	}
	return &connPool{instance: instance, limit: limit}
}

// Touch marks the pool as the active one and schedules a deferred refill.
func (p *connPool) Touch() {
	if p.limit <= 0 {
		return
	}
	setActivePool(p)
	p.access.Lock()
	if p.closed || p.timer != nil || p.filling || len(p.conns) >= p.limit {
		p.access.Unlock()
		return
	}
	p.timer = time.AfterFunc(poolFillDelay, p.fill)
	p.access.Unlock()
}

// Take pops a usable warm connection, closing expired ones.
func (p *connPool) Take() (net.Conn, bool) {
	p.access.Lock()
	defer p.access.Unlock()
	if p.closed {
		return nil, false
	}
	now := time.Now()
	for len(p.conns) > 0 {
		last := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		idleCount.Add(-1)
		if now.Sub(last.created) > poolIdleTimeout {
			common.Close(last.conn)
			continue
		}
		return last.conn, true
	}
	return nil, false
}

func (p *connPool) fill() {
	p.access.Lock()
	p.timer = nil
	if p.closed || p.limit <= 0 || p.filling || len(p.conns) >= p.limit {
		p.access.Unlock()
		return
	}
	p.filling = true
	p.access.Unlock()
	defer func() {
		p.access.Lock()
		p.filling = false
		p.access.Unlock()
	}()
	for {
		if !isActivePool(p) {
			return
		}
		p.access.Lock()
		capacity := !p.closed && len(p.conns) < p.limit && idleCount.Load() < poolIdleBudget
		p.access.Unlock()
		if !capacity {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := p.instance.dialTLS(ctx)
		cancel()
		if err != nil {
			return
		}
		p.access.Lock()
		if p.closed || len(p.conns) >= p.limit || idleCount.Load() >= poolIdleBudget {
			p.access.Unlock()
			common.Close(conn)
			return
		}
		p.conns = append(p.conns, pooledConn{conn: conn, created: time.Now()})
		idleCount.Add(1)
		p.access.Unlock()
		time.Sleep(poolFillInterval)
	}
}

func (p *connPool) closeIdle() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, entry := range p.conns {
		idleCount.Add(-1)
		common.Close(entry.conn)
	}
	p.conns = nil
}

func (p *connPool) Close() error {
	p.access.Lock()
	p.closed = true
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	conns := p.conns
	p.conns = nil
	p.access.Unlock()
	for _, entry := range conns {
		idleCount.Add(-1)
		common.Close(entry.conn)
	}
	activePoolAccess.Lock()
	if activePool == p {
		activePool = nil
	}
	activePoolAccess.Unlock()
	return nil
}

var _ io.Closer = (*connPool)(nil)
