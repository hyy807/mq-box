package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"

	restls "github.com/metacubex/restls-client-go"
)

type RESTLSClientConfig struct {
	config           *restls.Config
	serverName       string
	handshakeTimeout time.Duration
	clientID         restls.ClientHelloID
}

func (c *RESTLSClientConfig) ServerName() string { return c.serverName }
func (c *RESTLSClientConfig) SetServerName(name string) {
	c.serverName = name
	c.config.ServerName = name
}
func (c *RESTLSClientConfig) NextProtos() []string                      { return c.config.NextProtos }
func (c *RESTLSClientConfig) SetNextProtos(protocols []string)          { c.config.NextProtos = protocols }
func (c *RESTLSClientConfig) HandshakeTimeout() time.Duration           { return c.handshakeTimeout }
func (c *RESTLSClientConfig) SetHandshakeTimeout(timeout time.Duration) { c.handshakeTimeout = timeout }
func (c *RESTLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("RESTLS has no standard TLS config")
}
func (c *RESTLSClientConfig) Client(conn net.Conn) (Conn, error) {
	return &restlsConn{UConn: restls.UClient(conn, c.config.Clone(), c.clientID)}, nil
}
func (c *RESTLSClientConfig) Clone() Config {
	return &RESTLSClientConfig{config: c.config.Clone(), serverName: c.serverName, handshakeTimeout: c.handshakeTimeout, clientID: c.clientID}
}

type restlsConn struct{ *restls.UConn }

func (c *restlsConn) ConnectionState() tls.ConnectionState {
	state := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}
func (c *restlsConn) Upstream() any { return c.UConn.NetConn() }

func newRESTLSClient(ctx context.Context, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	if options.Engine != "" && options.Engine != C.TLSEngineGo {
		return nil, E.New("RESTLS requires Go TLS engine")
	}
	if options.DisableSNI || options.ECH != nil && options.ECH.Enabled || options.KernelRx || options.KernelTx || options.Spoof != "" || options.Fragment || options.RecordFragment {
		return nil, E.New("RESTLS does not support disable_sni, ECH, kTLS, spoof or fragmentation")
	}
	if options.UTLS != nil && options.UTLS.Enabled && options.UTLS.Fingerprint != "" && options.RESTLS.Fingerprint != "" && options.UTLS.Fingerprint != options.RESTLS.Fingerprint {
		return nil, E.New("conflicting RESTLS and uTLS fingerprints")
	}
	serverName := options.ServerName
	if serverName == "" {
		serverName = serverAddress
	}
	if serverName == "" {
		return nil, errMissingServerName
	}
	fingerprint := options.RESTLS.Fingerprint
	if fingerprint == "" && options.UTLS != nil && options.UTLS.Enabled {
		fingerprint = options.UTLS.Fingerprint
	}
	config, err := restls.NewRestlsConfig(serverName, options.RESTLS.Password, options.RESTLS.VersionHint, options.RESTLS.RESTLSScript, fingerprint)
	if err != nil {
		return nil, E.Cause(err, "parse RESTLS config")
	}
	config.Time = ntp.TimeFuncFromContext(ctx)
	config.RootCAs = adapter.RootPoolFromContext(ctx)
	config.InsecureSkipVerify = options.Insecure
	if len(options.ALPN) > 0 {
		config.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		config.MinVersion, err = ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, err
		}
	}
	if options.MaxVersion != "" {
		config.MaxVersion, err = ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, err
		}
	}
	if options.CertificateSHA256 != nil || options.CertificatePublicKeySHA256 != nil {
		return nil, E.New("RESTLS does not support certificate pinning")
	}
	if len(options.Certificate) > 0 || options.CertificatePath != "" {
		var cert []byte
		if len(options.Certificate) > 0 {
			cert = []byte(strings.Join(options.Certificate, "\n"))
		} else {
			cert, err = filemanager.ReadFile(ctx, options.CertificatePath)
			if err != nil {
				return nil, err
			}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cert) {
			return nil, E.New("invalid RESTLS CA certificate")
		}
		config.RootCAs = pool
	}
	if len(options.ClientCertificate) > 0 || options.ClientCertificatePath != "" || len(options.ClientKey) > 0 || options.ClientKeyPath != "" || len(options.CipherSuites) > 0 || len(options.CurvePreferences) > 0 {
		return nil, E.New("RESTLS does not support client certificates, custom cipher suites or curves")
	}
	var id restls.ClientHelloID = restls.HelloChrome_Auto
	if config.ClientID != nil && config.ClientID.Load() != nil {
		id = *config.ClientID.Load()
	}
	timeout := C.TCPTimeout
	if options.HandshakeTimeout > 0 {
		timeout = options.HandshakeTimeout.Build()
	}
	return &RESTLSClientConfig{config: config, serverName: serverName, handshakeTimeout: timeout, clientID: id}, nil
}
