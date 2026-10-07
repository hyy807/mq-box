package jumao

import (
	"context"
	"net"

	MC "github.com/sagernet/sing-box/mods/modconst"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/mods/modoption"
	T "github.com/sagernet/sing-box/mods/transport/jumao"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RegisterOutbound registers the 橘猫 (Jumao) outbound: shadowsocks aes-256-cfb
// with a watermarked first IV.
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.JumaoOutboundOptions](registry, MC.TypeJumao, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	password   string
	userID     uint32
	userPass   string
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.JumaoOutboundOptions) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, E.New("jumao[", tag, "]: password is required")
	}
	if options.UserPass == "" {
		return nil, E.New("jumao[", tag, "]: user_pass is required")
	}
	if options.UserID == 0 {
		return nil, E.New("jumao[", tag, "]: user_id is required")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(MC.TypeJumao, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		password:   options.Password,
		userID:     options.UserID,
		userPass:   options.UserPass,
	}, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("jumao: UDP is not implemented")
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, E.Cause(err, "connect to ", h.serverAddr)
		}
		streamConn, err := T.Handshake(rawConn, h.password, h.userID, h.userPass, destination)
		if err != nil {
			common.Close(rawConn)
			return nil, err
		}
		return streamConn, nil
	default:
		return nil, E.New("jumao: UDP is not implemented")
	}
}
