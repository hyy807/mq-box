// Package modtls is the TLS layer of the mq-box private protocols. Upstream
// common/tls is reused for plain TLS; JLS, RESTLS, the fixed REALITY client and
// the extra uTLS fingerprints live here so upstream TLS code stays untouched.
package modtls

import (
	"context"

	stls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/mods/modoption"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
)

type (
	Config = aTLS.Config
	Conn   = aTLS.Conn
)

// NewClient builds the TLS client of a private protocol. It returns nil when
// TLS is disabled.
func NewClient(ctx context.Context, logger log.ContextLogger, serverAddress string, options *modoption.ModTLSOptions) (Config, error) {
	if options == nil || !options.Enabled {
		return nil, nil
	}
	base := options.OutboundTLSOptions
	switch {
	case options.JLS != nil:
		return newJLSClient(ctx, serverAddress, base, options.JLS)
	case options.RESTLS != nil:
		if base.Reality != nil && base.Reality.Enabled {
			return nil, E.New("RESTLS is incompatible with reality")
		}
		return newRESTLSClient(ctx, serverAddress, base, options.RESTLS)
	case base.Reality != nil && base.Reality.Enabled:
		return newRealityClient(ctx, serverAddress, base)
	case base.UTLS != nil && base.UTLS.Enabled:
		return newUTLSClient(ctx, serverAddress, base, false)
	}
	return stls.NewClientWithOptions(stls.ClientOptions{Context: ctx, Logger: logger, ServerAddress: serverAddress, Options: base})
}
