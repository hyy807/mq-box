package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	jls "github.com/metacubex/jls-tls"
	"github.com/sagernet/sing-box/option"
	aTLS "github.com/sagernet/sing/common/tls"
)

func testJLSCertificate(t *testing.T) jls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com"}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := jls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestJLSClientIntegration(t *testing.T) {
	user := jls.JLSUser{Username: "alice", Password: "secret"}
	serverConfig := &jls.Config{Certificates: []jls.Certificate{testJLSCertificate(t)}, MinVersion: jls.VersionTLS13, NextProtos: []string{"h2"}, JLSConfig: &jls.JLSConfig{Enable: true, ServerName: "example.com", Users: []jls.JLSUser{user}}}
	for _, test := range []struct {
		name, password string
		success        bool
	}{{"accepted", user.Password, true}, {"rejected", "wrong", false}} {
		t.Run(test.name, func(t *testing.T) {
			clientConfig, err := newJLSClient(ClientOptions{Context: context.Background(), ServerAddress: "example.com", Options: option.OutboundTLSOptions{Enabled: true, ALPN: []string{"h2"}, JLS: &option.OutboundJLSOptions{Username: user.Username, Password: test.password}}})
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			serverResult := make(chan error, 1)
			go func() { server := jls.Server(left, serverConfig); serverResult <- server.Handshake() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := aTLS.ClientHandshake(ctx, right, clientConfig)
			if test.success {
				if err != nil {
					t.Fatal(err)
				}
				if client.ConnectionState().NegotiatedProtocol != "h2" {
					t.Fatalf("unexpected ALPN %q", client.ConnectionState().NegotiatedProtocol)
				}
				if serverErr := <-serverResult; serverErr != nil {
					t.Fatal(serverErr)
				}
			} else if !errors.Is(err, jls.ErrJLSAuthFailed) && err == nil {
				t.Fatalf("expected authentication failure, got %v", err)
			}
		})
	}
}

func TestJLSRejectsIncompatibleOptions(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*option.OutboundTLSOptions)
	}{
		{"missing password", func(o *option.OutboundTLSOptions) { o.JLS.Password = "" }},
		{"utls", func(o *option.OutboundTLSOptions) { o.UTLS = &option.OutboundUTLSOptions{Enabled: true} }},
		{"insecure", func(o *option.OutboundTLSOptions) { o.Insecure = true }},
		{"TLS 1.2", func(o *option.OutboundTLSOptions) { o.MaxVersion = "1.2" }},
		{"disable SNI", func(o *option.OutboundTLSOptions) { o.DisableSNI = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := option.OutboundTLSOptions{Enabled: true, JLS: &option.OutboundJLSOptions{Username: "alice", Password: "secret"}}
			test.change(&opts)
			if _, err := newJLSClient(ClientOptions{Context: context.Background(), ServerAddress: "example.com", Options: opts}); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
