// Package x365 implements the private `x365` outbound of the饿饭 / 365VPN
// (protocolabs OEM) white-label family.
//
// Wire contract (verified against the shipping client and byte-for-byte with
// the reference implementation):
//
//	REALITY (TLS1.3, uTLS chrome, SNI = disguise domain)
//	  └─ POST /<path> HTTP/1.1
//	     Host: <disguise domain>
//	     Content-Type: application/grpc
//	     Transfer-Encoding: chunked
//	       chunk 1: X365 handshake frame
//	       chunk n: real payload
//	     response first 5 bytes: raw "X365" + 1 status byte (0 = OK)
//	     response after that: raw payload (NOT chunked at the X365 layer)
//
// Handshake frame layout:
//
//	offset  size  value
//	0       4     "X365"
//	4       1     0x01 (version)
//	5       1     command        (1 = TCP, 2 = UDP, 3 = zero-address)
//	6       16    key16          (the UUID's own 16 bytes, not a hash)
//	22      ..    addrPort       (port big-endian, then atyp + address)
//
// A non-zero status byte must abort the connection.
package x365

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
	"github.com/sagernet/sing-box/mods/transport/x365http"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	frameMagic   = "X365"
	frameVersion = 0x01

	commandTCP  = 0x01
	commandUDP  = 0x02
	commandZero = 0x03

	statusOK = 0x00
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[modoption.X365OutboundOptions](registry, MC.TypeX365, NewOutbound)
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	key        [16]byte
	transport  *x365http.Client
	packetAddr bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options modoption.X365OutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("x365 requires TLS (REALITY)")
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
	if tlsConfig == nil {
		return nil, E.New("x365 requires TLS")
	}
	transport, err := x365http.NewClient(outboundDialer, options.ServerOptions.Build(), options.X365, tlsConfig)
	if err != nil {
		return nil, E.Cause(err, "create x365 transport")
	}
	h := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(MC.TypeX365, tag, options.Network.Build(), options.DialerOptions),
		logger:    logger,
		key:       key,
		transport: transport,
	}
	if options.PacketEncoding != nil {
		switch *options.PacketEncoding {
		case "", "packetaddr":
			h.packetAddr = true
		case "xudp":
			h.packetAddr = false
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
		conn, err := h.transport.DialContext(ctx)
		if err != nil {
			return nil, err
		}
		if err = h.writeHandshake(conn, commandTCP, destination); err != nil {
			conn.Close()
			return nil, err
		}
		// 参照上游 xhttp 的 DialStreamOne：不在 Dial 里同步等响应头，
		// 否则每次建连都多付一个 RTT（服务端要等够数据才发头）。
		// 改为首次 Read 时才验证 X365 状态头。
		return &lazyStatusConn{Conn: conn}, nil
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := h.transport.DialContext(ctx)
		if err != nil {
			return nil, err
		}
		if err = h.writeHandshake(conn, commandUDP, destination); err != nil {
			conn.Close()
			return nil, err
		}
		return &packetConn{Conn: &lazyStatusConn{Conn: conn}, destination: destination}, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// lazyStatusConn 把 X365 的 5 字节响应头校验从 Dial 推迟到首次读，
// 这样建连路径不再同步等待服务端响应（上游 xhttp DialStreamOne 的等价做法）。
type lazyStatusConn struct {
	net.Conn
	checked bool
}

func (c *lazyStatusConn) checkStatus() error {
	if c.checked {
		return nil
	}
	if err := readResponseHeader(c.Conn); err != nil {
		return err
	}
	c.checked = true
	return nil
}

func (c *lazyStatusConn) Read(p []byte) (int, error) {
	if err := c.checkStatus(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.transport.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	if err = h.writeHandshake(conn, commandZero, destination); err != nil {
		conn.Close()
		return nil, err
	}
	return &packetConn{Conn: &lazyStatusConn{Conn: conn}, destination: destination}, nil
}

// writeHandshake emits the X365 frame as the first chunk of the chunked body.
func (h *Outbound) writeHandshake(conn net.Conn, command byte, destination M.Socksaddr) error {
	frame := make([]byte, 0, 64)
	frame = append(frame, frameMagic...)
	frame = append(frame, frameVersion, command)
	frame = append(frame, h.key[:]...)
	if command != commandZero {
		frame = append(frame, serializeAddrPort(destination)...)
	}
	_, err := conn.Write(frame)
	if err != nil {
		return E.Cause(err, "write x365 handshake")
	}
	return nil
}

// serializeAddrPort writes port (big-endian) + atyp + address, matching the
// reference implementation recovered from core.dll (port BEFORE address).
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

// readResponseHeader consumes the server's "X365" + status byte prefix.
// A non-zero status byte means the account/session is rejected and the
// connection must be dropped.
func readResponseHeader(conn net.Conn) error {
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return E.Cause(err, "read x365 response header")
	}
	if string(header[:4]) != frameMagic {
		return E.New("invalid x365 response header: got ", hexPrefix(header[:4]))
	}
	if header[4] != statusOK {
		return E.New("x365: server rejected session, status=", header[4])
	}
	return nil
}

func hexPrefix(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		const hexDigits = "0123456789abcdef"
		sb.WriteByte(hexDigits[c>>4])
		sb.WriteByte(hexDigits[c&0x0f])
	}
	return sb.String()
}

// parseUUIDKey turns a UUID string into the raw 16 bytes used as the X365
// frame key field (NOT hashed).
func parseUUIDKey(value string) ([16]byte, error) {
	var key [16]byte
	cleaned := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(cleaned) != 32 {
		return key, E.New("x365: invalid UUID: ", value)
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return key, E.Cause(err, "x365: invalid UUID: ", value)
	}
	copy(key[:], decoded)
	return key, nil
}

// packetConn moves whole datagrams with a 2-byte big-endian length prefix,
// mirroring the reference implementation's UDP framing.
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
	return io.ReadFull(c.Conn, p[:length])
}

func (c *packetConn) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, E.New("x365: udp datagram too large")
	}
	packet := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(packet, uint16(len(p)))
	copy(packet[2:], p)
	_, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if c.destination.IsFqdn() {
		return n, c.destination, err
	}
	return n, c.destination.UDPAddr(), err
}

func (c *packetConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func (c *packetConn) Close() error { return c.Conn.Close() }
