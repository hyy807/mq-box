package onesocks

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/onesocks"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RegisterOutbound registers the provider's `type: os` outbound, plus the
// long form spelling `onesocks`.
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.OneSocksOutboundOptions](registry, C.TypeOneSocks, NewOutbound)
	outbound.Register[option.OneSocksOutboundOptions](registry, C.TypeOneSocksLong, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	key        []byte
	hmac       []byte
	padding    T.PaddingRange
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.OneSocksOutboundOptions) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, E.New("onesocks[", tag, "]: password is required")
	}
	keySize, err := T.CipherKeySize(options.Cipher)
	if err != nil {
		return nil, E.Cause(err, "onesocks[", tag, "]")
	}
	paddingRange, err := T.ParsePadding(options.PaddingLen)
	if err != nil {
		return nil, E.Cause(err, "onesocks[", tag, "]")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeOneSocks, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		key:        T.PasswordKey(options.Password, keySize),
		hmac:       T.PasswordHMAC(options.Password),
		padding:    paddingRange,
	}, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("onesocks: UDP is not implemented")
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, E.Cause(err, "connect to ", h.serverAddr)
		}
		streamConn, err := T.Dial(rawConn, h.key, h.hmac, h.padding, destination)
		if err != nil {
			common.Close(rawConn)
			return nil, err
		}
		return streamConn, nil
	default:
		return nil, E.New("onesocks: UDP is not implemented")
	}
}
