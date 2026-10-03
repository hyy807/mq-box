package xhttp

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/xstream"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HeysocksXhttpOutboundOptions](registry, C.TypeXhttp, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound implements the Heysocks (just4test) `type: xhttp` outbound.
//
// The reference kernel (llyufenggotest/sing-box, protocol/xhttp/outbound.go)
// carries this protocol over a PLAIN TCP connection — there is no TLS handshake
// at all. The opening flight is a 128 byte decoy TCP header followed by an MD5
// token, the raw HMAC key, the 0x10 IV marker and a 16 byte IV, after which
// everything (destination address included) is AES-CTR encrypted on one
// continuous keystream.
type Outbound struct {
	outbound.Adapter
	logger   logger.ContextLogger
	dialer   N.Dialer
	server   M.Socksaddr
	config   xstream.Config
	debug    bool
	debugTag string
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HeysocksXhttpOutboundOptions) (adapter.Outbound, error) {
	seed, extraHex, err := xstream.ParsePassword(options.Password)
	if err != nil {
		return nil, E.Cause(err, "xhttp[", tag, "]")
	}
	var fakeTCP string
	if options.FakeNet != nil {
		fakeTCP = options.FakeNet.TCP
	}
	config := xstream.Config{
		Seed:       seed,
		ExtraHex:   extraHex,
		FakeTCPHex: fakeTCP,
	}
	// Fail fast on malformed inputs instead of at dial time.
	if _, _, _, _, err = xstream.BuildFirstBlock(config, M.ParseSocksaddr("127.0.0.1:1")); err != nil {
		return nil, E.Cause(err, "xhttp[", tag, "]")
	}

	network := options.Network.Build()
	if len(network) == 0 {
		network = []string{N.NetworkTCP}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	if options.TLS != nil && options.TLS.Enabled {
		// The reference kernel never performs a TLS handshake for xhttp. The
		// provider payload still carries a tls block, so warn instead of
		// failing — the node only works over plain TCP.
		logger.Warn("xhttp[", tag, "]: tls is configured but this protocol is carried over plain TCP; the tls block is ignored")
	}
	if options.UDP {
		logger.Warn("xhttp[", tag, "]: udp is configured but the xstream UDP framing is not implemented, UDP traffic will be rejected")
	}
	return &Outbound{
		Adapter:  outbound.NewAdapterWithDialerOptions(C.TypeXhttp, tag, network, options.DialerOptions),
		logger:   logger,
		dialer:   outboundDialer,
		server:   options.ServerOptions.Build(),
		config:   config,
		debug:    options.DebugWire,
		debugTag: tag,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		return nil, E.New("xhttp: UDP is not implemented for this outbound")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}

	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.server)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	firstBlock, encryptStream, block, ivOffset, err := xstream.BuildFirstBlock(h.config, destination)
	if err != nil {
		rawConn.Close()
		return nil, E.Cause(err, "xhttp: build first block")
	}
	if h.debug {
		h.logger.Warn("xhttp diag[", h.debugTag, "]: first block ", len(firstBlock),
			" bytes (fake=", xstream.FakeHeaderLength, " marker_offset=", ivOffset, ")")
	}
	if _, err = rawConn.Write(firstBlock); err != nil {
		rawConn.Close()
		return nil, E.Cause(err, "xhttp: write first block")
	}
	// Never block here waiting for the server header: the first Read consumes it
	// lazily (reference conn.go).
	return xstream.NewConn(rawConn, encryptStream, block, ivOffset), nil
}

// ListenPacket is rejected: the xstream UDP framing is not established by the
// reference implementation.
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("xhttp: UDP is not implemented for this outbound")
}

func (h *Outbound) Close() error { return nil }

var _ = fmt.Sprintf
