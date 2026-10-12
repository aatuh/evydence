package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type collectorBindingActivity struct {
	calls     int
	collector CollectorActivity
	hook      func()
}

type collectorBindingReader struct {
	*fakeIdentityReader
	binding CollectorBinding
}

func (r collectorBindingReader) CollectorByAPIKey(context.Context, string, string) (CollectorBinding, bool, error) {
	return r.binding, true, nil
}

func (a *collectorBindingActivity) RecordAPIKeyUse(_ context.Context, _ identitydomain.APIKey, c CollectorActivity) error {
	a.calls++
	a.collector = c
	if a.hook != nil {
		a.hook()
	}
	return nil
}
func (*collectorBindingActivity) ValidateActiveSession(context.Context, identitydomain.SSOSession, time.Time) error {
	return nil
}

func TestCollectorAuthenticationRejectsInvalidInactiveOrBroaderCredentialBindingsBeforeActivity(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*CollectorBinding, *identitydomain.APIKey)
	}{
		{"disabled", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.Status = "disabled" }},
		{"revoked", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.Status = "revoked" }},
		{"unknown status", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.Status = "unknown" }},
		{"missing id", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.ID = "" }},
		{"blank id", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.ID = " " }},
		{"foreign tenant", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.TenantID = "foreign" }},
		{"foreign key", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.APIKeyID = "foreign" }},
		{"missing declared scopes", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.AllowedScopes = nil }},
		{"broader key", func(_ *CollectorBinding, k *identitydomain.APIKey) { k.Scopes = []string{"evidence:write", "admin"} }},
		{"wildcard key", func(_ *CollectorBinding, k *identitydomain.APIKey) { k.Scopes = []string{"*"} }},
		{"padded binding scope", func(b *CollectorBinding, _ *identitydomain.APIKey) { b.AllowedScopes = []string{" evidence:write "} }},
		{"oversized binding", func(b *CollectorBinding, _ *identitydomain.APIKey) {
			b.AllowedScopes = []string{strings.Repeat("x", 129)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := CollectorBinding{ID: "collector", TenantID: "tenant", APIKeyID: "key", Status: "active", AllowedScopes: []string{"evidence:write"}}
			key := identitydomain.APIKey{ID: "key", TenantID: "tenant", Prefix: "evy_secret", Hash: "stored-hash", Scopes: []string{"evidence:write"}}
			tc.edit(&binding, &key)
			reader := collectorBindingReader{fakeIdentityReader: &fakeIdentityReader{apiKeys: []identitydomain.APIKey{key}}, binding: binding}
			activity := &collectorBindingActivity{}
			a, err := NewAuthenticator(AuthenticationConfig{Reader: reader, Activity: activity, Credentials: fakeCredentials{}, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) })})
			if err != nil {
				t.Fatal(err)
			}
			actor, err := a.Authenticate(t.Context(), "evy_secret")
			if !errors.Is(err, ErrUnauthorized) || !reflect.DeepEqual(actor, identitydomain.Actor{}) || activity.calls != 0 {
				t.Fatal("invalid collector binding returned authority or activity", err, actor.CollectorID, activity.calls)
			}
		})
	}
}

func TestCollectorAuthenticationReturnsOnlyDetachedIssuedCapabilitiesAndActivityBinding(t *testing.T) {
	key := identitydomain.APIKey{ID: "key", TenantID: "tenant", Prefix: "evy_secret", Hash: "stored-hash", Scopes: []string{"evidence:write"}}
	reader := collectorBindingReader{fakeIdentityReader: &fakeIdentityReader{apiKeys: []identitydomain.APIKey{key}}, binding: CollectorBinding{ID: "collector", TenantID: "tenant", APIKeyID: "key", Status: "active", AllowedScopes: []string{"evidence:write", "source:read"}}}
	activity := &collectorBindingActivity{}
	a, err := NewAuthenticator(AuthenticationConfig{Reader: reader, Activity: activity, Credentials: fakeCredentials{}, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) })})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := a.Authenticate(t.Context(), "evy_secret")
	if err != nil || actor.CollectorID != "collector" || actor.TenantID != "tenant" || actor.KeyID != "key" || actor.UserID != "" || actor.SessionID != "" || len(actor.ResourceGrants) != 0 || !reflect.DeepEqual(actor.Scopes, []string{"evidence:write"}) || activity.calls != 1 || !reflect.DeepEqual(activity.collector.AllowedScopes, reader.binding.AllowedScopes) {
		t.Fatal("collector actor expanded or lost its bound capability snapshot", err)
	}
	reader.binding.AllowedScopes[0], key.Scopes[0] = "mutated", "mutated"
	if activity.collector.AllowedScopes[0] != "evidence:write" || actor.Scopes[0] != "evidence:write" {
		t.Fatal("authentication aliases stored credential/binding scopes")
	}
}

func TestCollectorAuthenticationWithholdsActorAfterActivityCancellation(t *testing.T) {
	key := identitydomain.APIKey{ID: "key", TenantID: "tenant", Prefix: "evy_secret", Hash: "stored-hash", Scopes: []string{"evidence:write"}}
	reader := collectorBindingReader{fakeIdentityReader: &fakeIdentityReader{apiKeys: []identitydomain.APIKey{key}}, binding: CollectorBinding{ID: "collector", TenantID: "tenant", APIKeyID: "key", Status: "active", AllowedScopes: []string{"evidence:write"}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	activity := &collectorBindingActivity{hook: cancel}
	a, err := NewAuthenticator(AuthenticationConfig{Reader: reader, Activity: activity, Credentials: fakeCredentials{}, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) })})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := a.Authenticate(ctx, "evy_secret")
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(actor, identitydomain.Actor{}) || activity.calls != 1 {
		t.Fatal("canceled activity returned an authenticated actor", err, activity.calls)
	}
}
