package mieru

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	MC "github.com/sagernet/sing-box/mods/modconst"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"google.golang.org/protobuf/proto"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.MieruOutboundOptions](registry, MC.TypeMieru, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	client mieruclient.Client
	logger log.ContextLogger
	mu     sync.Mutex
}

type streamDialer struct{ N.Dialer }

func (d streamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
}

type packetDialer struct{ N.Dialer }

func (d packetDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (net.PacketConn, error) {
	remote := M.ParseSocksaddr(raddr)
	if !remote.IsIP() {
		return nil, E.New("mieru: packet endpoint is not an IP address: ", raddr)
	}
	return d.Dialer.ListenPacket(ctx, remote)
}

type resolver struct{ router adapter.DNSRouter }

func (r resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	addresses, err := r.router.Lookup(ctx, host, adapter.DNSQueryOptions{})
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, net.IP(address.AsSlice()))
	}
	return ips, nil
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.MieruOutboundOptions) (adapter.Outbound, error) {
	profile, err := buildProfile(tag, options)
	if err != nil {
		return nil, err
	}
	client := mieruclient.NewClient()
	rawDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	config := &mieruclient.ClientConfig{
		Profile:      profile,
		Dialer:       streamDialer{rawDialer},
		PacketDialer: packetDialer{rawDialer},
		Resolver:     resolver{service.FromContext[adapter.DNSRouter](ctx)},
		DNSConfig:    &mierucommon.ClientDNSConfig{BypassDialerDNS: true},
	}
	if err := client.Store(config); err != nil {
		return nil, fmt.Errorf("mieru: store configuration: %w", err)
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(MC.TypeMieru, tag, options.Network.Build(), options.DialerOptions),
		client:  client,
		logger:  logger,
	}, nil
}

func buildProfile(tag string, options modoption.MieruOutboundOptions) (*mierupb.ClientProfile, error) {
	if options.Server == "" || options.Username == "" || options.Password == "" {
		return nil, E.New("mieru: server, username and password are required")
	}
	if (options.ServerPort == 0) == (options.PortRange == "") {
		return nil, E.New("mieru: exactly one of server_port and port_range is required")
	}
	var binding mierupb.PortBinding
	if options.PortRange != "" {
		parts := strings.Split(options.PortRange, "-")
		if len(parts) != 2 {
			return nil, E.New("mieru: invalid port_range")
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, E.New("mieru: invalid port_range")
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil || start < 1 || end > 65535 || start > end {
			return nil, E.New("mieru: invalid port_range")
		}
		binding.PortRange = proto.String(options.PortRange)
	} else {
		binding.Port = proto.Int32(int32(options.ServerPort))
	}
	switch options.Transport {
	case "TCP":
		binding.Protocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		binding.Protocol = mierupb.TransportProtocol_UDP.Enum()
	default:
		return nil, E.New("mieru: transport must be TCP or UDP")
	}
	server := &mierupb.ServerEndpoint{PortBindings: []*mierupb.PortBinding{&binding}}
	if ip, err := netip.ParseAddr(options.Server); err == nil {
		server.IpAddress = proto.String(ip.String())
	} else {
		server.DomainName = proto.String(options.Server)
	}
	profile := &mierupb.ClientProfile{
		ProfileName: proto.String(tag),
		User:        &mierupb.User{Name: proto.String(options.Username), Password: proto.String(options.Password)},
		Servers:     []*mierupb.ServerEndpoint{server},
	}
	if options.Multiplexing != "" {
		value, ok := mierupb.MultiplexingLevel_value[options.Multiplexing]
		if !ok {
			return nil, E.New("mieru: invalid multiplexing level: ", options.Multiplexing)
		}
		profile.Multiplexing = &mierupb.MultiplexingConfig{Level: mierupb.MultiplexingLevel(value).Enum()}
	}
	if options.HandshakeMode != "" {
		value, ok := mierupb.HandshakeMode_value[options.HandshakeMode]
		if !ok {
			return nil, E.New("mieru: invalid handshake mode: ", options.HandshakeMode)
		}
		profile.HandshakeMode = mierupb.HandshakeMode(value).Enum()
	}
	if options.TrafficPattern != "" {
		pattern, err := mierutp.Decode(options.TrafficPattern)
		if err != nil {
			return nil, err
		}
		if err := mierutp.Validate(pattern); err != nil {
			return nil, err
		}
		profile.TrafficPattern = pattern
	}
	return profile, nil
}

func (o *Outbound) start() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client.IsRunning() {
		return nil
	}
	if err := o.client.Start(); err != nil {
		return fmt.Errorf("mieru: start client: %w", err)
	}
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	if err := o.start(); err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		return o.client.DialContext(ctx, mierumodel.NetAddrSpec{AddrSpec: addressSpec(destination), Net: N.NetworkTCP})
	case N.NetworkUDP:
		packet, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packet, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func addressSpec(destination M.Socksaddr) mierumodel.AddrSpec {
	if destination.IsIP() {
		return mierumodel.AddrSpec{IP: net.IP(destination.Addr.AsSlice()), Port: int(destination.Port)}
	}
	return mierumodel.AddrSpec{FQDN: destination.Fqdn, Port: int(destination.Port)}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	if err := o.start(); err != nil {
		return nil, err
	}
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := o.client.DialContext(ctx, mierumodel.NetAddrSpec{AddrSpec: addressSpec(destination), Net: N.NetworkUDP})
	if err != nil {
		return nil, err
	}
	return mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(conn)), nil
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client.IsRunning() {
		return o.client.Stop()
	}
	return nil
}
