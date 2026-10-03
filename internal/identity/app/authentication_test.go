package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestStandaloneAuthenticatorUsesFocusedCredentialDependencies(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		reader     *fakeIdentityReader
		wantKeyID  string
		wantUserID string
	}{
		{
			name: "API key with collector",
			reader: &fakeIdentityReader{
				apiKeys:   []identitydomain.APIKey{{ID: "key_1", TenantID: "ten_1", Prefix: "evy_secret", Hash: "stored-hash", Scopes: []string{"product:read"}}},
				collector: CollectorBinding{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_1"},
			},
			wantKeyID: "key_1",
		},
		{
			name: "human session with scoped grant",
			reader: &fakeIdentityReader{
				sessions: []identitydomain.SSOSession{{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", ExpiresAt: now.Add(time.Hour)}},
				sessionIdentity: SessionIdentity{
					User:   identitydomain.HumanUser{ID: "usr_1", TenantID: "ten_1", Status: "active"},
					Grants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"product:read"}}},
				},
			},
			wantUserID: "usr_1",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			transactions := &fakeIdentityTransactions{state: newFakeIdentityState()}
			authenticator, err := NewAuthenticator(AuthenticationConfig{
				Reader: test.reader, Activity: transactionAuthenticationActivity{transactions: transactions}, Credentials: fakeCredentials{},
				Clock: application.ClockFunc(func() time.Time { return now }),
			})
			if err != nil {
				t.Fatal(err)
			}
			actor, err := authenticator.Authenticate(t.Context(), "Bearer evy_secret")
			if err != nil || actor.TenantID != "ten_1" || actor.KeyID != test.wantKeyID || actor.UserID != test.wantUserID || !actor.HasScope("product:read") || transactions.commits != 1 {
				t.Fatalf("actor=%#v commits=%d error=%v", actor, transactions.commits, err)
			}
			if test.wantUserID != "" && (len(actor.ResourceGrants) != 1 || actor.ResourceGrants[0].ResourceID != "prod_1") {
				t.Fatalf("session grants=%#v", actor.ResourceGrants)
			}
		})
	}
}

func TestStandaloneAuthenticatorRequiresCredentialBoundaries(t *testing.T) {
	reader := &fakeIdentityReader{}
	transactions := &fakeIdentityTransactions{state: newFakeIdentityState()}
	activity := transactionAuthenticationActivity{transactions: transactions}
	clock := application.ClockFunc(func() time.Time { return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC) })
	for _, config := range []AuthenticationConfig{
		{Activity: activity, Credentials: fakeCredentials{}, Clock: clock},
		{Reader: reader, Credentials: fakeCredentials{}, Clock: clock},
		{Reader: reader, Activity: activity, Clock: clock},
		{Reader: reader, Activity: activity, Credentials: fakeCredentials{}},
	} {
		if authenticator, err := NewAuthenticator(config); !errors.Is(err, ErrValidation) || authenticator != nil {
			t.Fatalf("unsafe authenticator=%#v error=%v", authenticator, err)
		}
	}
}

func TestStandaloneAuthenticatorDoesNotExposeActivityFailure(t *testing.T) {
	reader := &fakeIdentityReader{apiKeys: []identitydomain.APIKey{{ID: "key_1", TenantID: "ten_1", Prefix: "evy_secret", Hash: "stored-hash"}}}
	transactions := &fakeIdentityTransactions{state: newFakeIdentityState(), err: errors.New("private database detail")}
	authenticator, err := NewAuthenticator(AuthenticationConfig{
		Reader: reader, Activity: transactionAuthenticationActivity{transactions: transactions}, Credentials: fakeCredentials{},
		Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(t.Context(), "evy_secret"); !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "private database detail") {
		t.Fatalf("unsafe authentication error=%v", err)
	}
}
