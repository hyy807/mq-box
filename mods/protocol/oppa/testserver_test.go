package oppa

import (
	"crypto/tls"
	"net"
	"time"
)

// tlsServerSide performs the server side of the TLS handshake with a short
// deadline, returning nil on failure.
func tlsServerSide(conn net.Conn, certificate tls.Certificate) *tls.Conn {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}
	_ = conn.SetDeadline(time.Time{})
	return tlsConn
}
