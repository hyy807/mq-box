package aha

import "context"

// Discovery obtains account-specific data-plane credentials and a node.
// HubDiscovery is the default; an app may inject its authenticated client.
// It must perform signin -> access (persistent token) -> node and must never
// use a signin token as a data-plane token. Credentials come from SecretStore.
// The access response schema is not documented by the supplied reference:
// HubDiscovery accepts only explicitly labelled persistent credentials.
type Discovery interface {
	Discover(ctx context.Context, username, password, region string) (Endpoint, error)
}

type Endpoint struct {
	Backend   string
	Port      uint16
	Handshake HandshakeOptions
}

type discoveryKey struct{}

func WithDiscovery(ctx context.Context, client Discovery) context.Context {
	return context.WithValue(ctx, discoveryKey{}, client)
}
func DiscoveryFromContext(ctx context.Context) Discovery {
	client, _ := ctx.Value(discoveryKey{}).(Discovery)
	return client
}
