package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type delayedSessionCommitActivity struct{ after func() }

func (delayedSessionCommitActivity) RecordAPIKeyUse(context.Context, identitydomain.APIKey, CollectorActivity) error {
	return nil
}
func (d delayedSessionCommitActivity) ValidateActiveSession(_ context.Context, _ identitydomain.SSOSession, _ SessionIdentity, clock application.Clock) (time.Time, error) {
	used := clock.Now()
	d.after()
	return used, nil
}

func TestAuthenticatorWithholdsActorWhenCommitOutlivesSession(t *testing.T) {
	for _, elapsed := range []time.Duration{30 * time.Minute, time.Hour} {
		f := newIdentityServiceFixture(t)
		at := f.now
		f.reader.sessions = []identitydomain.SSOSession{{ID: "session", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", CreatedAt: at, ExpiresAt: at.Add(time.Hour)}}
		f.reader.sessionIdentity = activeSessionIdentity("ten_1")
		authenticator, err := NewAuthenticator(AuthenticationConfig{Reader: f.reader, Activity: delayedSessionCommitActivity{after: func() { at = at.Add(elapsed) }}, Credentials: fakeCredentials{}, Clock: application.ClockFunc(func() time.Time { return at })})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := authenticator.Authenticate(t.Context(), "evy_secret")
		if !errors.Is(err, ErrUnauthorized) || actor.UserID != "" {
			t.Fatal("late committed admission returned an inactive actor", err)
		}
	}
}

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
				collector: CollectorBinding{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_1", Status: "active", AllowedScopes: []string{"product:read"}},
			},
			wantKeyID: "key_1",
		},
		{
			name: "human session with scoped grant",
			reader: &fakeIdentityReader{
				sessions: []identitydomain.SSOSession{{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}},
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

func TestAuthenticatorRejectsIdleAndOverLifetimeSessions(t *testing.T) {
	for _, test := range []struct {
		name                        string
		createdOffset, expiryOffset time.Duration
	}{
		{"idle boundary", -30 * time.Minute, time.Hour},
		{"idle elapsed", -time.Hour, time.Hour},
		{"over maximum lifetime", -time.Hour, 12 * time.Hour},
		{"future creation", time.Minute, time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newIdentityServiceFixture(t)
			f.reader.sessions = []identitydomain.SSOSession{{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", ProviderID: "provider", Prefix: "evy_secret", Hash: "stored-hash", CreatedAt: f.now.Add(test.createdOffset), ExpiresAt: f.now.Add(test.expiryOffset)}}
			f.reader.sessionIdentity = activeSessionIdentity("ten_1")
			actor, err := f.service.Authenticate(t.Context(), "evy_secret")
			if !errors.Is(err, ErrUnauthorized) || actor.UserID != "" || f.transactions.commits != 0 {
				t.Fatalf("inactive session admitted: error=%v commits=%d", err, f.transactions.commits)
			}
		})
	}
}
