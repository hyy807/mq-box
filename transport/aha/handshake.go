package aha

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/tls"
)

type HandshakeOptions struct {
	Host, UID, AccessToken, Device, Platform, Version, TunnelIP, TunnelGateway string
}

func BackendHost(host string) string {
	if strings.HasSuffix(host, ".baidu.com") {
		return strings.TrimSuffix(host, ".baidu.com") + ".wishadmin.com"
	}
	return host
}

func (o HandshakeOptions) Validate() error {
	values := []string{o.Host, o.UID, o.AccessToken, o.Device, o.Platform, o.Version, o.TunnelIP, o.TunnelGateway}
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("aha: missing or invalid handshake field")
		}
	}
	if strings.ContainsAny(o.Host, " /\t") {
		return fmt.Errorf("aha: invalid camouflage host")
	}
	for _, value := range []string{o.TunnelIP, o.TunnelGateway} {
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("aha: tunnel addresses must be IPv4")
		}
	}
	return nil
}

// Handshake performs TLS then sends headers only. The peer is silent: do not
// read an HTTP status line, otherwise the first TCP SYN can never be sent.
// Ownership of raw transfers to the returned connection; failures close it.
func Handshake(ctx context.Context, raw net.Conn, config tls.Config, o HandshakeOptions) (net.Conn, error) {
	if err := o.Validate(); err != nil {
		raw.Close()
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := handshakeCtx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return nil, err
	}
	stop := context.AfterFunc(handshakeCtx, func() { raw.Close() })
	defer stop()
	conn, err := tls.ClientHandshake(handshakeCtx, raw, config)
	if err != nil {
		raw.Close()
		return nil, err
	}
	headers := fmt.Sprintf("GET /api/tunnel/data HTTP/1.1\r\nHost: %s\r\nCx-UID: %s\r\nCx-App: ahaspeed\r\nCx-Token: %s\r\nCx-Device: %s\r\nCx-Platform: %s\r\nCx-Version: %s\r\nCx-Tunnel-IP: %s\r\nCx-Tunnel-Gateway: %s\r\nConnection: keep-alive\r\n\r\n", o.Host, o.UID, o.AccessToken, o.Device, o.Platform, o.Version, o.TunnelIP, o.TunnelGateway)
	if err = WriteAll(conn, []byte(headers)); err != nil {
		conn.Close()
		return nil, err
	}
	if !stop() || handshakeCtx.Err() != nil {
		conn.Close()
		return nil, handshakeCtx.Err()
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
