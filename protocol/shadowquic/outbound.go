package shadowquic

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	quic "github.com/metacubex/jls-quic-go"
	jls "github.com/metacubex/jls-tls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ShadowQUICOutboundOptions](registry, C.TypeShadowQUIC, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	server     M.Socksaddr
	tlsConfig  *jls.Config
	quicConfig *quic.Config
	client     *Client
	zeroRTT    bool
	mu         sync.Mutex
	packetConn net.PacketConn
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowQUICOutboundOptions) (adapter.Outbound, error) {
	if options.Server == "" || options.ServerPort == 0 || options.Username == "" || options.Password == "" {
		return nil, E.New("shadowquic requires server, server_port, username and password")
	}
	if options.CongestionController != "" || options.Up != "" || options.Down != "" || options.CWND != 0 || options.BBRProfile != "" {
		return nil, E.New("shadowquic custom congestion and brutal are not supported")
	}
	versions := []quic.Version{quic.Version1}
	if len(options.QUICVersions) > 0 {
		versions = nil
		for _, v := range options.QUICVersions {
			switch strings.ToLower(v) {
			case "v1", "1", "rfc9000", "rfc-9000":
				versions = append(versions, quic.Version1)
			case "v2", "2", "rfc9369", "rfc-9369":
				versions = append(versions, quic.Version2)
			default:
				return nil, E.New("unsupported shadowquic QUIC version: ", v)
			}
		}
	}
	serverName := options.SNI
	if serverName == "" {
		serverName = options.Server
	}
	alpn := options.ALPN
	if alpn == nil {
		alpn = []string{"h3"}
	}
	d, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	q := &quic.Config{Versions: versions, EnableDatagrams: true, DisablePathMTUDiscovery: options.DisableMTUDiscovery, MaxDatagramFrameSize: options.MaxDatagramFrameSize, MaxIncomingStreams: options.MaxOpenStreams, MaxIncomingUniStreams: options.MaxOpenStreams}
	if q.MaxDatagramFrameSize == 0 {
		q.MaxDatagramFrameSize = 1400
	}
	if q.MaxIncomingStreams == 0 {
		q.MaxIncomingStreams = 1024
		q.MaxIncomingUniStreams = 1024
	}
	if options.ReceiveWindowConn > 0 {
		q.InitialStreamReceiveWindow = options.ReceiveWindowConn
		q.MaxStreamReceiveWindow = options.ReceiveWindowConn
	}
	if options.ReceiveWindow > 0 {
		q.InitialConnectionReceiveWindow = options.ReceiveWindow
		q.MaxConnectionReceiveWindow = options.ReceiveWindow
	}
	if options.KeepAliveInterval > 0 {
		q.KeepAlivePeriod = time.Duration(options.KeepAliveInterval) * time.Millisecond
	}
	t := &jls.Config{ServerName: serverName, NextProtos: alpn, MinVersion: jls.VersionTLS13, JLSConfig: &jls.JLSConfig{Enable: true, User: jls.JLSUser{Username: options.Username, Password: options.Password}}}
	if options.ZeroRTT {
		t.ClientSessionCache = jls.NewLRUClientSessionCache(1)
	}
	o := &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeShadowQUIC, tag, options.Network.Build(), options.DialerOptions), logger: logger, dialer: d, server: options.ServerOptions.Build(), tlsConfig: t, quicConfig: q, zeroRTT: options.ZeroRTT}
	o.client = NewClient(&ClientOption{Dial: o.dialQUIC, UDPOverStream: options.UDPOverStream})
	return o, nil
}
func (o *Outbound) dialQUIC(ctx context.Context) (*quic.Conn, error) {
	pc, err := o.dialer.ListenPacket(ctx, o.server)
	if err != nil {
		return nil, err
	}
	remoteAddr := o.server
	if remoteAddr.IsDomain() {
		addresses, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", remoteAddr.Fqdn)
		if lookupErr != nil {
			pc.Close()
			return nil, lookupErr
		}
		if len(addresses) == 0 {
			pc.Close()
			return nil, E.New("shadowquic server DNS returned no addresses")
		}
		remoteAddr = M.SocksaddrFrom(addresses[0], remoteAddr.Port)
	}
	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(remoteAddr.Addr, remoteAddr.Port))
	tr := &quic.Transport{Conn: pc}
	var conn *quic.Conn
	if o.zeroRTT {
		conn, err = tr.DialEarly(ctx, remote, o.tlsConfig, o.quicConfig)
	} else {
		conn, err = tr.Dial(ctx, remote, o.tlsConfig, o.quicConfig)
	}
	if err != nil {
		tr.Close()
		pc.Close()
		return nil, err
	}
	if !o.zeroRTT && conn.ConnectionState().TLS.JLS.Status != jls.JLSAuthenticated {
		conn.CloseWithError(0, "auth failed")
		tr.Close()
		pc.Close()
		return nil, jls.ErrJLSAuthFailed
	}
	o.mu.Lock()
	o.packetConn = pc
	o.mu.Unlock()
	if o.zeroRTT {
		go func() {
			select {
			case <-conn.HandshakeComplete():
				if conn.ConnectionState().TLS.JLS.Status != jls.JLSAuthenticated {
					conn.CloseWithError(0, "auth failed")
				}
			case <-conn.Context().Done():
			}
		}()
	}
	go func() { <-conn.Context().Done(); tr.Close(); pc.Close() }()
	return conn, nil
}
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		return o.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		pc, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(pc, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return o.client.ListenPacket(ctx, destination)
}
func (o *Outbound) InterfaceUpdated(ctx context.Context) { o.client.Reset() }
func (o *Outbound) Close() error {
	o.client.Close()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.packetConn != nil {
		return o.packetConn.Close()
	}
	return nil
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)
