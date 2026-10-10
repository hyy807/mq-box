// Package vlessx365 adapts the饿饭 / 365VPN X365 deployment onto the *standard*
// VLESS protocol laid out by sing-vmess, instead of defining a parallel private
// protocol.
//
// The structure is the upstream VLESS one — the same Client/Conn/Request shape,
// the same DialEarlyConn entry points, the same command bytes, the same
// destination addressing. Only the request header is a maker modification:
//
//	upstream VLESS request        X365 maker request
//	------------------------      --------------------------
//	0        version (0x00)       0      'X','3','6','5'  magic
//	1..16    UUID (16 bytes)      4      version (0x01)
//	17       addonsLen            5      command (1=TCP,2=UDP,3=zero-addr)
//	18..     addons (protobuf)    6..21  UUID key (16 raw bytes)
//	..       command              ..     addrPort
//	..       addrPort
//
// The response header keeps the same idea (a magic + status instead of VLESS's
// version + addonsLen):
//
//	'X','3','6','5' status      (status 0 == OK)
//
// Everything above the header — the payload handling, the packet framing, the
// net.Conn semantics — is the standard VLESS behaviour. Upstream `protocol/vless`
// is not edited: this outbound is registered separately.
package vlessx365

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	MC "github.com/sagernet/sing-box/mods/modconst"
	"github.com/sagernet/sing-box/mods/modoption"
	"github.com/sagernet/sing-box/mods/modtls"
	"github.com/sagernet/sing-box/mods/transport/v2rayxhttp"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// X365 maker constants. The request magic is upper-case, the response magic is
// lower-case — verified against the shipping server.
const (
	requestMagic  = "X365"
	responseMagic = "X365"

	frameVersion = 0x01

	commandTCP  = 0x01
	commandUDP  = 0x02
	commandZero = 0x03

	statusOK = 0x00
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.VLESSX365OutboundOptions](registry, MC.TypeVLESSX365, NewOutbound)
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	key        [16]byte
	transport  *v2rayxhttp.Client
	packetAddr bool
	xudp       bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.VLESSX365OutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("vless-x365 requires TLS")
	}
	key, err := parseUUIDKey(options.UUID)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := modtls.NewClient(ctx, logger, options.Server, options.TLS)
	if err != nil {
		return nil, err
	}
	transport, err := v2rayxhttp.NewClient(outboundDialer, options.ServerOptions.Build(), options.XHTTP, tlsConfig)
	if err != nil {
		return nil, E.Cause(err, "create xhttp carrier")
	}
	h := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(MC.TypeVLESSX365, tag, options.Network.Build(), options.DialerOptions),
		logger:    logger,
		key:       key,
		transport: transport,
	}
	if options.PacketEncoding == nil {
		h.xudp = true
	} else {
		switch *options.PacketEncoding {
		case "":
		case "packetaddr":
			h.packetAddr = true
		case "xudp":
			h.xudp = true
		default:
			return nil, E.New("unknown packet encoding: ", *options.PacketEncoding)
		}
	}
	return h, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(h.transport.Close)
	}
	return nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.transport.Close()
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := h.dialTransport(ctx)
		if err != nil {
			return nil, err
		}
		return h.dialEarlyConn(conn, commandTCP, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.listenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.listenPacket(ctx, destination)
}

func (h *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.dialTransport(ctx)
	if err != nil {
		return nil, err
	}
	if h.xudp {
		remoteConn, err := h.dialEarlyConnRaw(conn, commandTCP, destination)
		if err != nil {
			return nil, err
		}
		return vmess.NewXUDPConn(remoteConn, destination), nil
	} else if h.packetAddr {
		if destination.IsDomain() {
			conn.Close()
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		remoteConn, err := h.dialEarlyConnRaw(conn, commandTCP, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(&packetConn{Conn: remoteConn, destination: destination}, destination), nil
	}
	remoteConn, err := h.dialEarlyConnRaw(conn, commandUDP, destination)
	if err != nil {
		return nil, err
	}
	return &packetConn{Conn: remoteConn, destination: destination}, nil
}

func (h *Outbound) dialTransport(ctx context.Context) (net.Conn, error) {
	conn, err := h.transport.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// dialEarlyConn writes the X365 request header and returns the connection whose
// Read strips the X365 response header first — the same lazy semantics as
// upstream vless.DialEarlyConn.
func (h *Outbound) dialEarlyConn(conn net.Conn, command byte, destination M.Socksaddr) (net.Conn, error) {
	header := buildRequestHeader(h.key, command, destination)
	_, err := conn.Write(header)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "write x365 request header")
	}
	return &statusConn{Conn: conn}, nil
}

func (h *Outbound) dialEarlyConnRaw(conn net.Conn, command byte, destination M.Socksaddr) (net.Conn, error) {
	return h.dialEarlyConn(conn, command, destination)
}

// buildRequestHeader serialises the maker-modified VLESS request header:
// magic("X365") + version + command + uuid key + addrPort.
func buildRequestHeader(key [16]byte, command byte, destination M.Socksaddr) []byte {
	out := make([]byte, 0, 64)
	out = append(out, requestMagic...)
	out = append(out, frameVersion, command)
	out = append(out, key[:]...)
	if command != commandZero {
		out = append(out, serializeAddrPort(destination)...)
	}
	return out
}

// serializeAddrPort writes port (big-endian) + atyp + address, matching the
// shipping server (port BEFORE address, unlike upstream VLESS).
func serializeAddrPort(destination M.Socksaddr) []byte {
	var out []byte
	out = append(out, byte(destination.Port>>8), byte(destination.Port))
	if destination.IsFqdn() {
		out = append(out, 0x02) // atyp domain
		fqdn := destination.Fqdn
		if len(fqdn) > 255 {
			fqdn = fqdn[:255]
		}
		out = append(out, byte(len(fqdn)))
		out = append(out, fqdn...)
		return out
	}
	addr := destination.Addr
	if addr.Is4() {
		out = append(out, 0x01) // atyp IPv4
		out = append(out, addr.AsSlice()...)
		return out
	}
	out = append(out, 0x03) // atyp IPv6
	out = append(out, addr.AsSlice()...)
	return out
}

// statusConn strips the X365 response header on the first Read:
// 0x04 + "x365" + version + status, and aborts on a non-zero status.
type statusConn struct {
	net.Conn
	headerRead bool
}

func (c *statusConn) Read(b []byte) (int, error) {
	if !c.headerRead {
		c.headerRead = true
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, E.Cause(err, "read x365 response header")
		}
		if string(header[0:4]) != responseMagic {
			return 0, E.New("x365: unexpected response header: ", hex.EncodeToString(header[:]))
		}
		if header[4] != statusOK {
			return 0, E.New("x365: server rejected the request, status=", header[4])
		}
	}
	return c.Conn.Read(b)
}

// packetConn carries length-prefixed datagrams, the standard 2-byte big-endian
// framing used by the X365 server for UDP.
type packetConn struct {
	net.Conn
	destination M.Socksaddr
}

func (c *packetConn) Read(p []byte) (int, error) {
	var size [2]byte
	if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if len(p) < length {
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(c.Conn, p[:length]); err != nil {
		return 0, err
	}
	return length, nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if err != nil {
		return 0, nil, err
	}
	return n, c.destination.UDPAddr(), nil
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.Write(p)
}

func (c *packetConn) Write(p []byte) (int, error) {
	if len(p) > 0xFFFF {
		return 0, E.New("x365: packet too large")
	}
	buffer := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buffer, uint16(len(p)))
	copy(buffer[2:], p)
	if _, err := c.Conn.Write(buffer); err != nil {
		return 0, err
	}
	return len(p), nil
}

// parseUUIDKey converts the configured UUID into the 16 raw bytes the X365
// frame carries (no hashing).
func parseUUIDKey(value string) ([16]byte, error) {
	var key [16]byte
	cleaned := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(cleaned) != 32 {
		return key, E.New("vless-x365: invalid UUID: ", value)
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return key, E.Cause(err, "vless-x365: invalid UUID: ", value)
	}
	copy(key[:], decoded)
	return key, nil
}
