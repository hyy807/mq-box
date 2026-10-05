package aha

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/aha"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ahaHandshakeTimeout = 7 * time.Second
	ahaProbeTimeout     = 5 * time.Second
	// Entries go stale and are reachable from different networks independently, so
	// a bounded set is raced in parallel and the first working tunnel wins.
	ahaCandidateLimit = 6
	ahaAttemptLimit   = 12
)

// ahaDataPorts are the TLS data-plane ports seen open on the provider's hosts.
// A host may advertise a camouflage port that is closed, so the advertised value
// is only the first candidate.
var ahaDataPorts = []uint16{3306, 6379, 443}

func sameNodeIdentity(a, b string) bool {
	a = strings.ToLower(strings.TrimSuffix(a, ".wishadmin.com"))
	b = strings.ToLower(strings.TrimSuffix(b, ".wishadmin.com"))
	a = strings.TrimSuffix(a, ".baidu.com")
	b = strings.TrimSuffix(b, ".baidu.com")
	return a == b
}

func ahaPortCandidates(port uint16) []uint16 {
	var ports []uint16
	for _, candidate := range append([]uint16{port}, ahaDataPorts...) {
		if candidate == 0 {
			continue
		}
		duplicate := false
		for _, existing := range ports {
			if existing == candidate {
				duplicate = true
				break
			}
		}
		if !duplicate {
			ports = append(ports, candidate)
		}
	}
	return ports
}

// RegisterOutbound only supplies a migration error for old configurations.
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AHAOutboundOptions](registry, C.TypeAHA, NewOutbound)
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, o option.AHAOutboundOptions) (adapter.Outbound, error) {
	return newTunnel(ctx, logger, tag, o)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	options   option.AHAOutboundOptions
	node      string
	discovery T.Discovery
	dialer    N.Dialer
	// preferredAddress is the tunnel address the caller already bound to its TUN
	// device; using it first keeps the device address valid without reconfiguring.
	preferredAddress string
}

func newTunnel(ctx context.Context, logger log.ContextLogger, tag string, o option.AHAEndpointOptions) (*Outbound, error) {
	if o.Username == "" || o.Password == "" {
		return nil, fmt.Errorf("aha[%s]: username and password are required", tag)
	}
	discovery := T.DiscoveryFromContext(ctx)
	d, err := dialer.New(ctx, o.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	if discovery == nil {
		discovery = &T.HubDiscovery{Dialer: d}
	}
	return &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeAHA, tag, []string{N.NetworkTCP}, o.DialerOptions), ctx: ctx, logger: logger, options: o, node: o.Node, discovery: discovery, dialer: d}, nil
}

// candidates orders the discovered nodes so the configured one is tried first and
// every sibling in the same region remains a fallback: individual entries go stale
// or become unreachable independently.
func (h *Outbound) candidates(ctx context.Context) ([]T.Endpoint, error) {
	// A plaintext node needs no discovery at all: the profile already carries the
	// entry to dial and its camouflage identity. Only the account session is
	// fetched, once per account for every endpoint.
	if h.options.Backend != "" {
		if h.options.Host == "" {
			return nil, fmt.Errorf("aha: a plaintext node needs host and backend")
		}
		credentials, err := h.accountToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("aha: account discovery failed: %w", err)
		}
		port := h.options.Port
		if port == 0 {
			port = 3306
		}
		return []T.Endpoint{{
			Backend: h.options.Backend,
			Port:    port,
			Node:    h.options.Backend,
			Handshake: T.HandshakeOptions{
				Host: h.options.Host, UID: credentials.UID, AccessToken: credentials.Token,
				Device: credentials.Device, Platform: "windows", Version: "3.13.0",
				TunnelIP: T.RandomTunnelAddress(), TunnelGateway: T.TunnelGateway,
			},
		}}, nil
	}
	return h.discoveredCandidates(ctx)
}

// accountToken returns the account session from whatever discovery was injected.
func (h *Outbound) accountToken(ctx context.Context) (T.Session, error) {
	if source, ok := h.discovery.(T.TokenSource); ok {
		return source.Token(ctx, h.options.Username, h.options.Password)
	}
	endpoint, err := h.discovery.Discover(ctx, h.options.Username, h.options.Password, h.options.Region)
	if err != nil {
		return T.Session{}, err
	}
	return T.Session{Token: endpoint.Handshake.AccessToken, UID: endpoint.Handshake.UID, Device: endpoint.Handshake.Device}, nil
}

func (h *Outbound) discoveredCandidates(ctx context.Context) ([]T.Endpoint, error) {
	multi, multiOK := h.discovery.(T.MultiDiscovery)
	if h.node == "" {
		if multiOK {
			endpoints, err := multi.DiscoverAll(ctx, h.options.Username, h.options.Password, h.options.Region)
			if err == nil && len(endpoints) > 0 {
				return endpoints, nil
			}
		}
		endpoint, err := h.discovery.Discover(ctx, h.options.Username, h.options.Password, h.options.Region)
		if err != nil {
			return nil, fmt.Errorf("aha: account discovery failed: %w", err)
		}
		return []T.Endpoint{endpoint}, nil
	}
	if !multiOK {
		return nil, fmt.Errorf("aha: node selection requires multi-node discovery")
	}
	endpoints, err := multi.DiscoverAll(ctx, h.options.Username, h.options.Password, h.options.Region)
	if err != nil {
		return nil, fmt.Errorf("aha: account discovery failed: %w", err)
	}
	var ordered []T.Endpoint
	for _, candidate := range endpoints {
		if sameNodeIdentity(candidate.Node, h.node) || sameNodeIdentity(candidate.Backend, h.node) {
			ordered = append(ordered, candidate)
		}
	}
	if len(ordered) == 0 {
		// A configured name that no entry matches (display names change and differ from
		// the entry hostname) must not fail startup: the region's entries are still usable.
		h.logger.Debug("aha: configured node ", h.node, " is not in the discovered set, using the region")
		return endpoints, nil
	}
	for _, candidate := range endpoints {
		known := false
		for _, selected := range ordered {
			if selected.Backend == candidate.Backend && selected.Port == candidate.Port {
				known = true
				break
			}
		}
		if !known {
			ordered = append(ordered, candidate)
		}
	}
	return ordered, nil
}

type ahaAttempt struct {
	endpoint T.Endpoint
	port     uint16
	address  string
}

// DialTunnel discovers account-specific credentials and opens the raw IPv4
// data plane. Never return this directly as an application TCP stream.
func (h *Outbound) dialTunnel(ctx context.Context) (net.Conn, T.Endpoint, error) {
	return h.dialTunnelPreferred(ctx, h.preferredAddress)
}

// dialTunnelForProbe opens a tunnel for a latency probe. It never offers the
// address the endpoint's data plane holds: the peer treats a second session
// claiming that address as a takeover and stops NATing the first one, which
// silently kills a working data plane.
func (h *Outbound) dialTunnelForProbe(ctx context.Context) (net.Conn, T.Endpoint, error) {
	return h.dialTunnelPreferred(ctx, "")
}

func (h *Outbound) dialTunnelPreferred(ctx context.Context, preferredAddress string) (net.Conn, T.Endpoint, error) {
	candidates, err := h.candidates(ctx)
	if err != nil {
		return nil, T.Endpoint{}, err
	}
	var plan []ahaAttempt
	var lastErr error
	candidates = candidates[:min(len(candidates), ahaCandidateLimit)]
	for _, endpoint := range candidates {
		if err = endpoint.Handshake.Validate(); err != nil {
			lastErr = err
			continue
		}
		ports := ahaPortCandidates(endpoint.Port)
		if len(ports) > 2 {
			ports = ports[:2]
		}
		for _, port := range ports {
			// The advertised tunnel address may already be held by another session;
			// the server then refuses the handshake, so a fresh address is offered.
			address := T.RandomTunnelAddress()
			if len(plan) == 0 && preferredAddress != "" {
				address = preferredAddress
			}
			plan = append(plan, ahaAttempt{endpoint, port, address})
		}
	}
	if len(plan) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("aha: discovery returned no usable node")
		}
		return nil, T.Endpoint{}, lastErr
	}
	if len(plan) > ahaAttemptLimit {
		plan = plan[:ahaAttemptLimit]
	}
	type outcome struct {
		conn     net.Conn
		endpoint T.Endpoint
		address  string
		err      error
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	outcomes := make(chan outcome, len(plan))
	for _, attempt := range plan {
		go func(attempt ahaAttempt) {
			conn, err := h.openTunnel(raceCtx, attempt)
			outcomes <- outcome{conn, attempt.endpoint, attempt.address, err}
		}(attempt)
	}
	for range plan {
		result := <-outcomes
		if result.err == nil {
			cancel()
			// Losers finish in the background; close anything that still connects.
			go func() {
				for remaining := range outcomes {
					if remaining.conn != nil {
						remaining.conn.Close()
					}
				}
			}()
			// The endpoint must report the address the server actually accepted; the
			// caller assigns it to the tunnel device and the peer NATs to that value.
			endpoint := result.endpoint
			endpoint.Handshake.TunnelIP = result.address
			return result.conn, endpoint, nil
		}
		lastErr = result.err
	}
	return nil, T.Endpoint{}, fmt.Errorf("aha: no usable node: %w", lastErr)
}

func (h *Outbound) openTunnel(ctx context.Context, attempt ahaAttempt) (net.Conn, error) {
	handshake := attempt.endpoint.Handshake
	handshake.TunnelIP = attempt.address
	tlsOptions := option.OutboundTLSOptions{Enabled: true}
	if h.options.TLS != nil {
		tlsOptions = *h.options.TLS
	}
	if !tlsOptions.Enabled {
		return nil, fmt.Errorf("aha: TLS is required for the data plane")
	}
	for _, alpn := range tlsOptions.ALPN {
		if alpn != "http/1.1" {
			return nil, fmt.Errorf("aha: only HTTP/1.1 ALPN is supported")
		}
	}
	// The server selects the tunnel from the camouflage SNI while its certificate is
	// issued for the provider host, so a verified handshake can never match a working
	// vhost. The session is authenticated by the account token, not by the certificate.
	tlsOptions.ServerName = handshake.Host
	tlsOptions.Insecure = true
	config, err := tls.NewClient(h.ctx, h.logger, handshake.Host, tlsOptions)
	if err != nil {
		return nil, err
	}
	attemptCtx, cancel := context.WithTimeout(ctx, ahaHandshakeTimeout)
	defer cancel()
	raw, err := h.dialer.DialContext(attemptCtx, N.NetworkTCP, M.ParseSocksaddrHostPort(attempt.endpoint.Backend, attempt.port))
	if err != nil {
		return nil, err
	}
	conn, err := T.Handshake(attemptCtx, raw, config, handshake)
	if err != nil {
		return nil, err
	}
	probeCtx, cancelProbe := context.WithTimeout(attemptCtx, ahaProbeTimeout)
	defer cancelProbe()
	if err = T.ProbeTunnel(probeCtx, conn, attempt.address); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (*Outbound) DialContext(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, fmt.Errorf("aha: UDP is not implemented")
	}
	return nil, fmt.Errorf("aha: TCP-to-IPv4 bridge is not implemented; raw L3 tunnel is available through DialTunnel")
}

func (*Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("aha: UDP/ListenPacket is not implemented")
}
