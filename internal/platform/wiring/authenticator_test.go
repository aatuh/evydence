package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type authenticationReaderStub struct{ key identitydomain.APIKey }

func (r authenticationReaderStub) APIKeysByPrefix(context.Context, string) ([]identitydomain.APIKey, error) {
	return []identitydomain.APIKey{r.key}, nil
}
func (authenticationReaderStub) SessionsByPrefix(context.Context, string) ([]identitydomain.SSOSession, error) {
	return nil, nil
}
func (authenticationReaderStub) CollectorByAPIKey(context.Context, string, string) (identityapp.CollectorBinding, bool, error) {
	return identityapp.CollectorBinding{}, false, nil
}
func (authenticationReaderStub) SessionIdentity(context.Context, identitydomain.SSOSession) (identityapp.SessionIdentity, error) {
	return identityapp.SessionIdentity{}, nil
}

type authenticationActivityStub struct{}

func (authenticationActivityStub) RecordAPIKeyUse(context.Context, identitydomain.APIKey, identityapp.CollectorActivity) error {
	return nil
}
func (authenticationActivityStub) ValidateActiveSession(context.Context, identitydomain.SSOSession, time.Time) error {
	return nil
}

func TestBuildAuthenticatorRequiresPortsAndMatchesLocalPepper(t *testing.T) {
	if authenticator, err := BuildAuthenticator(nil, authenticationActivityStub{}, "test-pepper", false); !errors.Is(err, identityapp.ErrValidation) || authenticator != nil {
		t.Fatalf("nil reader authenticator=%#v error=%v", authenticator, err)
	}
	if authenticator, err := BuildAuthenticator(authenticationReaderStub{}, nil, "test-pepper", false); !errors.Is(err, identityapp.ErrValidation) || authenticator != nil {
		t.Fatalf("nil activity authenticator=%#v error=%v", authenticator, err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials(identityapp.LocalDevelopmentPepper)
	if err != nil {
		t.Fatal(err)
	}
	reader := authenticationReaderStub{key: identitydomain.APIKey{
		ID: "key_1", TenantID: "ten_1", Prefix: credentials.Prefix("evy_secret"),
		Hash: credentials.Hash("evy_secret"), Scopes: []string{"product:read"},
	}}
	if authenticator, err := BuildAuthenticator(reader, authenticationActivityStub{}, "", true); !errors.Is(err, identityapp.ErrValidation) || authenticator != nil {
		t.Fatalf("production default-pepper authenticator=%#v error=%v", authenticator, err)
	}
	if authenticator, err := BuildAuthenticator(reader, authenticationActivityStub{}, identityapp.LocalDevelopmentPepper, true); !errors.Is(err, identityapp.ErrValidation) || authenticator != nil {
		t.Fatalf("production explicit local-pepper authenticator=%#v error=%v", authenticator, err)
	}
	authenticator, err := BuildAuthenticator(reader, authenticationActivityStub{}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := authenticator.Authenticate(t.Context(), "evy_secret")
	if err != nil || actor.KeyID != "key_1" || actor.TenantID != "ten_1" {
		t.Fatalf("local-compatibility actor=%#v error=%v", actor, err)
	}
}
