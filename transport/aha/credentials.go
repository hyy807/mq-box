package aha

import (
	"context"
	"fmt"
)

// Credentials belong to a single account. Stores must not log these values.
type Credentials struct{ Username, Password string }

// CredentialStore is implemented by the host application's persistent secret
// store (for example iOS Keychain). The core never writes a second secret copy.
// Selecting another account requires a new endpoint/config reload, which closes
// the previous tunnel and performs fresh discovery.
type CredentialStore interface {
	LoadAHAAccount(context.Context, string) (Credentials, error)
}

type credentialStoreKey struct{}

func WithCredentialStore(ctx context.Context, store CredentialStore) context.Context {
	return context.WithValue(ctx, credentialStoreKey{}, store)
}
func ResolveCredentials(ctx context.Context, account, username, password string) (Credentials, error) {
	if account != "" {
		if username != "" || password != "" {
			return Credentials{}, fmt.Errorf("aha: account reference conflicts with inline credentials")
		}
		store, _ := ctx.Value(credentialStoreKey{}).(CredentialStore)
		if store == nil {
			return Credentials{}, fmt.Errorf("aha: account reference requires credential store")
		}
		credentials, err := store.LoadAHAAccount(ctx, account)
		if err != nil {
			return Credentials{}, fmt.Errorf("aha: cannot load account credentials")
		}
		username, password = credentials.Username, credentials.Password
	}
	if username == "" || password == "" {
		return Credentials{}, fmt.Errorf("aha: username and password are required")
	}
	return Credentials{username, password}, nil
}
