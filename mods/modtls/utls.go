package modtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	stls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

// utlsConfig is the private uTLS client of mq-box. It is a reduced copy of the
// upstream uTLS client that additionally knows the older Chrome fingerprints
// the private servers pin (chrome_106 & co). Upstream code is not touched.
type utlsConfig struct {
	ctx              context.Context
	config           *utls.Config
	serverName       string
	disableSNI       bool
	verifyServerName bool
	handshakeTimeout time.Duration
	id               utls.ClientHelloID
	strictALPN       bool
}

var _ Config = (*utlsConfig)(nil)

func (c *utlsConfig) ServerName() string { return c.serverName }

func (c *utlsConfig) SetServerName(serverName string) {
	c.serverName = serverName
	if c.disableSNI {
		c.config.ServerName = ""
		if c.verifyServerName {
			c.config.InsecureServerNameToVerify = serverName
		} else {
			c.config.InsecureServerNameToVerify = ""
		}
		return
	}
	c.config.ServerName = serverName
}

func (c *utlsConfig) NextProtos() []string { return c.config.NextProtos }

func (c *utlsConfig) SetNextProtos(nextProto []string) {
	if !c.strictALPN && len(nextProto) == 1 && nextProto[0] == http2.NextProtoTLS {
		nextProto = append(nextProto, "http/1.1")
	}
	c.config.NextProtos = nextProto
}

// SetNextProtosOnly sets ALPN without the implicit http/1.1 fallback, for
// HTTP/2-only carriers.
func (c *utlsConfig) SetNextProtosOnly(nextProto []string) {
	c.config.NextProtos = append([]string(nil), nextProto...)
}

func (c *utlsConfig) HandshakeTimeout() time.Duration           { return c.handshakeTimeout }
func (c *utlsConfig) SetHandshakeTimeout(timeout time.Duration) { c.handshakeTimeout = timeout }

func (c *utlsConfig) STDConfig() (*stls.STDConfig, error) {
	return nil, E.New("unsupported usage for uTLS")
}

func (c *utlsConfig) Client(conn net.Conn) (Conn, error) {
	return &utlsALPNConn{utlsConn{utls.UClient(conn, c.config.Clone(), c.id)}, c.config.NextProtos}, nil
}

func (c *utlsConfig) SetSessionIDGenerator(generator func(clientHello []byte, sessionID []byte) error) {
	c.config.SessionIDGenerator = generator
}

func (c *utlsConfig) Clone() Config {
	cloned := *c
	cloned.config = c.config.Clone()
	cloned.SetServerName(cloned.serverName)
	return &cloned
}

type utlsConn struct {
	*utls.UConn
}

func (c *utlsConn) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
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

func (c *utlsConn) Upstream() any           { return c.UConn }
func (c *utlsConn) ReaderReplaceable() bool { return true }
func (c *utlsConn) WriterReplaceable() bool { return true }

type utlsALPNConn struct {
	utlsConn
	nextProtocols []string
}

func (c *utlsALPNConn) HandshakeContext(ctx context.Context) error {
	if len(c.nextProtocols) > 0 {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
		for _, extension := range c.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = c.nextProtocols
				err = c.BuildHandshakeState()
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return c.UConn.HandshakeContext(ctx)
}

func newUTLSClient(ctx context.Context, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (*utlsConfig, error) {
	if options.Fragment || options.RecordFragment || options.Spoof != "" || options.KernelTx || options.KernelRx {
		return nil, E.New("fragment, spoof and kTLS are not supported by the private uTLS client")
	}
	if options.ECH != nil && options.ECH.Enabled {
		return nil, E.New("ECH is not supported by the private uTLS client")
	}
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure && !allowEmptyServerName {
		return nil, E.New("missing server_name or insecure=true")
	}
	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}
	if len(options.CertificateSHA256) > 0 || len(options.CertificatePublicKeySHA256) > 0 {
		if len(options.Certificate) > 0 || options.CertificatePath != "" {
			return nil, E.New("certificate_sha256 or certificate_public_key_sha256 is conflict with certificate or certificate_path")
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return stls.VerifyPinnedCertificate(options.CertificateSHA256, options.CertificatePublicKeySHA256, rawCerts)
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		v, err := stls.ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = v
	}
	if options.MaxVersion != "" {
		v, err := stls.ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = v
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, s := range tls.CipherSuites() {
				if cipherSuite == s.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, s.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate")
		}
		tlsConfig.RootCAs = certPool
	}
	handshakeTimeout := C.TCPTimeout
	if options.HandshakeTimeout > 0 {
		handshakeTimeout = options.HandshakeTimeout.Build()
	}
	var fingerprint string
	if options.UTLS != nil {
		fingerprint = options.UTLS.Fingerprint
	}
	id, err := ClientHelloID(fingerprint)
	if err != nil {
		return nil, err
	}
	config := &utlsConfig{
		ctx:              ctx,
		config:           &tlsConfig,
		serverName:       serverName,
		disableSNI:       options.DisableSNI,
		verifyServerName: options.DisableSNI && !options.Insecure,
		handshakeTimeout: handshakeTimeout,
		id:               id,
	}
	config.SetServerName(serverName)
	return config, nil
}

var randomFingerprint utls.ClientHelloID

func init() {
	modern := []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloEdge_Auto, utls.HelloSafari_Auto, utls.HelloIOS_Auto}
	randomFingerprint = modern[rand.Intn(len(modern))]
}

// ClientHelloID resolves a fingerprint name. Besides the upstream names it
// accepts the explicit Chrome versions used by the private servers.
func ClientHelloID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome_106", "chrome106", "chrome_106_shuffle", "chrome_shuffle":
		// The reference Heysocks kernel links an older uTLS in which
		// HelloChrome_Auto is HelloChrome_106_Shuffle.
		return utls.HelloChrome_106_Shuffle, nil
	case "chrome_100":
		return utls.HelloChrome_100, nil
	case "chrome_102":
		return utls.HelloChrome_102, nil
	case "chrome_100_psk":
		return utls.HelloChrome_100_PSK, nil
	case "chrome_112_psk_shuffle":
		return utls.HelloChrome_112_PSK_Shuf, nil
	case "chrome_114_padding_psk_shuffle":
		return utls.HelloChrome_114_Padding_PSK_Shuf, nil
	case "chrome_115_pq":
		return utls.HelloChrome_115_PQ, nil
	case "chrome_120":
		return utls.HelloChrome_120, nil
	case "chrome_120_pq":
		return utls.HelloChrome_120_PQ, nil
	case "chrome_131":
		return utls.HelloChrome_131, nil
	case "chrome_133":
		return utls.HelloChrome_133, nil
	case "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk", "chrome", "":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random":
		return randomFingerprint, nil
	case "randomized":
		return utls.HelloRandomized, nil
	default:
		return utls.ClientHelloID{}, E.New("unknown uTLS fingerprint: ", name)
	}
}
