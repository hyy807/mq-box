package tls

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	jls "github.com/metacubex/jls-tls"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
)

type jlsClientConfig struct {
	config           *jls.Config
	serverName       string
	handshakeTimeout time.Duration
}

func newJLSClient(options ClientOptions) (Config, error) {
	o := options.Options
	if o.JLS.Username == "" || o.JLS.Password == "" {
		return nil, E.New("jls requires username and password")
	}
	if o.Engine != "" && o.Engine != C.TLSEngineGo || o.UTLS != nil && o.UTLS.Enabled || o.Reality != nil && o.Reality.Enabled || o.ECH != nil && o.ECH.Enabled || o.KernelTx || o.KernelRx || o.Fragment || o.RecordFragment || o.Spoof != "" {
		return nil, E.New("jls is incompatible with the selected TLS options")
	}
	serverName := o.ServerName
	if serverName == "" {
		serverName = options.ServerAddress
	}
	if serverName == "" || o.DisableSNI {
		return nil, E.New("jls requires a server name and SNI")
	}
	if o.MinVersion != "" && o.MinVersion != "1.3" || o.MaxVersion != "" && o.MaxVersion != "1.3" {
		return nil, E.New("jls requires TLS 1.3")
	}
	if o.Insecure || len(o.Certificate) > 0 || o.CertificatePath != "" || len(o.CertificateSHA256) > 0 || len(o.CertificatePublicKeySHA256) > 0 || len(o.ClientCertificate) > 0 || o.ClientCertificatePath != "" || len(o.ClientKey) > 0 || o.ClientKeyPath != "" {
		return nil, E.New("jls does not support custom certificate verification or client certificates")
	}
	alpn := []string(o.ALPN)
	if o.ALPN == nil {
		alpn = []string{"h2", "http/1.1"}
	}
	handshakeTimeout := C.TCPTimeout
	if o.HandshakeTimeout > 0 {
		handshakeTimeout = o.HandshakeTimeout.Build()
	}
	return &jlsClientConfig{
		serverName:       serverName,
		handshakeTimeout: handshakeTimeout,
		config: &jls.Config{
			ServerName: serverName,
			NextProtos: append([]string(nil), alpn...),
			MinVersion: jls.VersionTLS13,
			Time:       ntp.TimeFuncFromContext(options.Context),
			JLSConfig:  &jls.JLSConfig{Enable: true, User: jls.JLSUser{Username: o.JLS.Username, Password: o.JLS.Password}},
		},
	}, nil
}

func (c *jlsClientConfig) ServerName() string { return c.serverName }
func (c *jlsClientConfig) SetServerName(value string) {
	c.serverName = value
	c.config.ServerName = value
}
func (c *jlsClientConfig) NextProtos() []string                    { return c.config.NextProtos }
func (c *jlsClientConfig) SetNextProtos(value []string)            { c.config.NextProtos = value }
func (c *jlsClientConfig) HandshakeTimeout() time.Duration         { return c.handshakeTimeout }
func (c *jlsClientConfig) SetHandshakeTimeout(value time.Duration) { c.handshakeTimeout = value }
func (c *jlsClientConfig) STDConfig() (*tls.Config, error) {
	return nil, E.New("jls requires its own TLS implementation")
}
func (c *jlsClientConfig) Clone() Config {
	return &jlsClientConfig{config: c.config.Clone(), serverName: c.serverName, handshakeTimeout: c.handshakeTimeout}
}
func (c *jlsClientConfig) Client(conn net.Conn) (Conn, error) {
	return &jlsConn{Conn: jls.Client(conn, c.config.Clone())}, nil
}
func (c *jlsClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (Conn, error) {
	client, _ := c.Client(conn)
	if err := client.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

type jlsConn struct{ *jls.Conn }

func (c *jlsConn) HandshakeContext(ctx context.Context) error {
	if err := c.Conn.HandshakeContext(ctx); err != nil {
		return err
	}
	if c.Conn.ConnectionState().JLS.Status != jls.JLSAuthenticated {
		return jls.ErrJLSAuthFailed
	}
	return nil
}
func (c *jlsConn) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:            state.Version,
		HandshakeComplete:  state.HandshakeComplete,
		DidResume:          state.DidResume,
		CipherSuite:        state.CipherSuite,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
		PeerCertificates:   state.PeerCertificates,
		VerifiedChains:     state.VerifiedChains,
	}
}
