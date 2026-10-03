package oppa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/oppa"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Test password and vectors from the protocol specification, section 8.
const (
	testPassword = "0123456789abcdef0123456789abcdef"
	testAuthHex  = "3031323334353637383961626364656630313233343536373839616263646566"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", value, err)
	}
	return decoded
}

func newTestOutbound(t *testing.T, server string, port uint16, password string, udp bool) *Outbound {
	t.Helper()
	instance, err := NewOutbound(context.Background(), nil, logger.NOP(), "test", option.OppaOutboundOptions{
		ServerOptions: option.ServerOptions{Server: server, ServerPort: port},
		Password:      password,
		UDP:           udp,
		PreConnect:    0,
	})
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	return instance.(*Outbound)
}

// TestLocalServerHandshake verifies the vendor compatible ClientHello (no SNI,
// no ALPN) and the exact first bytes written after the TLS handshake, as
// required by the acceptance list of the protocol specification.
func TestLocalServerHandshake(t *testing.T) {
	certificate := selfSignedCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			if info.ServerName != "" {
				t.Errorf("ClientHello sent SNI %q, want none", info.ServerName)
			}
			if len(info.SupportedProtos) > 0 {
				t.Errorf("ClientHello sent ALPN %v, want none", info.SupportedProtos)
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	instance := newTestOutbound(t, "127.0.0.1", uint16(address.Port), testPassword, false)

	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			received <- nil
			return
		}
		defer conn.Close()
		header := make([]byte, 128)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, readErr := conn.Read(header)
		if readErr != nil {
			received <- nil
			return
		}
		received <- header[:n]
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := instance.DialContext(ctx, N.NetworkTCP, M.Socksaddr{Fqdn: "capture.invalid", Port: 18082})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	var raw []byte
	select {
	case raw = <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not receive request")
	}
	expected := decodeHex(t, testAuthHex+"01"+"030f"+"636170747572652e696e76616c6964"+"46a2")
	if len(raw) < len(expected) || hex.EncodeToString(raw[:len(expected)]) != hex.EncodeToString(expected) {
		t.Fatalf("request mismatch\n got %s\nwant %s", hex.EncodeToString(raw), hex.EncodeToString(expected))
	}
}

// TestLocalServerUDPChannel verifies the UDP channel header and frame layout
// against a local TLS receiver, including two coalesced frames.
func TestLocalServerUDPChannel(t *testing.T) {
	certificate := selfSignedCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	instance := newTestOutbound(t, "127.0.0.1", uint16(address.Port), testPassword, true)

	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		channelHeader := make([]byte, T.PasswordSize+1)
		if _, readErr := io.ReadFull(conn, channelHeader); readErr != nil {
			received <- nil
			return
		}
		payload := append([]byte{}, channelHeader...)
		frameBuffer := make([]byte, 64)
		n, readErr := conn.Read(frameBuffer)
		if readErr != nil {
			received <- nil
			return
		}
		payload = append(payload, frameBuffer[:n]...)
		received <- payload
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packetConn, err := instance.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()
	udpConn, isUDPConn := packetConn.(*T.UDPConn)
	if !isUDPConn {
		t.Fatalf("ListenPacket returned %T", packetConn)
	}
	if err = udpConn.WritePacketBytes([]byte("DYNAMIC_UDP_0"), M.SocksaddrFrom(netip.MustParseAddr("127.0.0.2"), 18084)); err != nil {
		t.Fatalf("write first frame: %v", err)
	}
	var raw []byte
	select {
	case raw = <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not receive frame")
	}
	expectedHeader := decodeHex(t, testAuthHex+"02")
	if hex.EncodeToString(raw[:len(expectedHeader)]) != hex.EncodeToString(expectedHeader) {
		t.Fatalf("channel header mismatch\n got %s\nwant %s", hex.EncodeToString(raw), hex.EncodeToString(expectedHeader))
	}
	channel, destination, payload, err := T.DecodeUDPFrame(strings.NewReader(string(raw[len(expectedHeader):])))
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	// The channel address carries the session socket address, not a constant.
	if !channel.IsIPv4() || channel.Port == 0 {
		t.Fatalf("channel address %s, want the local socket address", channel)
	}
	t.Logf("channel address %s", channel)
	if destination.String() != "127.0.0.2:18084" || string(payload) != "DYNAMIC_UDP_0" {
		t.Fatalf("frame %s %s %q", channel, destination, payload)
	}
}

// TestLiveNode performs one real handshake plus HTTP request through a real
// node. It is opt-in: OPPA_LIVE_NODE=host:port OPPA_LIVE_PASSWORD=... go test
func TestLiveNode(t *testing.T) {
	endpoint := os.Getenv("OPPA_LIVE_NODE")
	if endpoint == "" {
		t.Skip("OPPA_LIVE_NODE is not set")
	}
	password := os.Getenv("OPPA_LIVE_PASSWORD")
	host, portValue, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("invalid OPPA_LIVE_NODE %q: %v", endpoint, err)
	}
	portNumber, err := strconv.Atoi(portValue)
	if err != nil {
		t.Fatalf("invalid port in %q: %v", endpoint, err)
	}
	instance := newTestOutbound(t, host, uint16(portNumber), password, false)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	target := M.Socksaddr{Fqdn: "captive.apple.com", Port: 80}
	conn, err := instance.DialContext(ctx, N.NetworkTCP, target)
	if err != nil {
		t.Fatalf("dial %s via %s: %v", target, endpoint, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	_, err = conn.Write([]byte("GET /hotspot-detect.html HTTP/1.1\r\nHost: captive.apple.com\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"))
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Logf("live response %d bytes: %s", len(response), firstLine(string(response)))
	if !strings.Contains(string(response), "HTTP/1.") {
		t.Fatalf("unexpected response: %q", response)
	}
}

// TestLiveNodeUDP sends one DNS query through the real UDP-over-TLS channel.
// It is opt-in: OPPA_LIVE_NODE=host:port OPPA_LIVE_PASSWORD=... go test
func TestLiveNodeUDP(t *testing.T) {
	endpoint := os.Getenv("OPPA_LIVE_NODE")
	if endpoint == "" {
		t.Skip("OPPA_LIVE_NODE is not set")
	}
	password := os.Getenv("OPPA_LIVE_PASSWORD")
	host, portValue, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("invalid OPPA_LIVE_NODE %q: %v", endpoint, err)
	}
	portNumber, err := strconv.Atoi(portValue)
	if err != nil {
		t.Fatalf("invalid port in %q: %v", endpoint, err)
	}
	instance := newTestOutbound(t, host, uint16(portNumber), password, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	packetConn, err := instance.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()
	udpConn := packetConn.(*T.UDPConn)
	query := decodeHex(t, "123401000001000000000000076578616d706c6503636f6d0000010001")
	if err = udpConn.WritePacketBytes(query, M.SocksaddrFrom(netip.MustParseAddr("8.8.8.8"), 53)); err != nil {
		t.Fatalf("write DNS query: %v", err)
	}
	_ = udpConn.SetReadDeadline(time.Now().Add(12 * time.Second))
	buffer := buf.NewSize(4096)
	defer buffer.Release()
	destination, err := udpConn.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("read DNS response: %v", err)
	}
	response := buffer.Bytes()
	t.Logf("UDP response from %s: %d bytes, %s", destination, len(response), hex.EncodeToString(response[:12]))
	if len(response) < 12 || response[0] != 0x12 || response[1] != 0x34 {
		t.Fatalf("unexpected DNS response: %s", hex.EncodeToString(response))
	}
	if response[3]&0x0F != 0 {
		t.Fatalf("DNS rcode %d", response[3]&0x0F)
	}
}

func firstLine(value string) string {
	if index := strings.IndexAny(value, "\r\n"); index >= 0 {
		return value[:index]
	}
	return value
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	return certificate
}

var _ = outbound.Adapter{}
