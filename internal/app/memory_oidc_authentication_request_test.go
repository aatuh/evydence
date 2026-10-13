package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemoryOIDCAuthenticationRequestEnforcesOwnershipAndSingleUse(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Identity.(interface {
		identityapp.OIDCAuthenticationRequestReader
		identityapp.OIDCAuthenticationRequestConsumer
		InsertOIDCAuthenticationRequest(tctx context.Context, v identitydomain.OIDCAuthenticationRequest, at time.Time) error
	})
	if !ok {
		t.Fatal("memory identity lacks bounded login request capability")
	}
	at := fixedNow()
	p := identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "oidc", Status: "active", Issuer: "https://issuer.example.test", ClientID: "client", JWKS: map[string]any{"keys": []any{map[string]any{"kid": "public"}}}, CreatedAt: at}
	tx.state.SSOProviders[p.ID] = domain.SSOProvider(p)
	fingerprint, err := identityapp.OIDCProviderTrustFingerprint(p)
	if err != nil {
		t.Fatal(err)
	}
	v := identitydomain.OIDCAuthenticationRequest{ID: "request", TenantID: p.TenantID, ProviderID: p.ID, Delivery: "api", TrustFingerprint: fingerprint, StateHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NonceHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute), SchemaVersion: identitydomain.OIDCAuthenticationRequestSchemaVersion}
	if err := r.InsertOIDCAuthenticationRequest(t.Context(), v, at); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadOIDCAuthenticationRequest(t.Context(), "foreign", p.ID, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign request was readable", err)
	}
	clock := application.ClockFunc(func() time.Time { return at.Add(time.Minute) })
	if _, err := r.ConsumeOIDCAuthenticationRequest(t.Context(), v, clock); err != nil {
		t.Fatal(err)
	}
	got, err := r.ReadOIDCAuthenticationRequest(t.Context(), p.TenantID, p.ID, v.ID)
	if err != nil || got.ConsumedAt == nil || got.StateHash != v.StateHash {
		t.Fatal("request material was not preserved", err)
	}
	*got.ConsumedAt = at.Add(time.Hour)
	if _, err := r.ConsumeOIDCAuthenticationRequest(t.Context(), v, clock); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("consumed request was replayable", err)
	}
	cloned, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil || cloned.OIDCAuthenticationRequests[v.ID].StateHash != v.StateHash || !cloned.OIDCAuthenticationRequests[v.ID].ConsumedAt.Equal(clock.Now()) {
		t.Fatal("transaction copy lost private material or aliased state", err)
	}
}

func TestMemoryOIDCRequestPortsRejectNilContextAndRepository(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	for _, r := range []memoryIdentityRepository{{uow: tx}, {}} {
		for _, call := range []func(context.Context) error{
			func(ctx context.Context) error { return r.ValidateOIDCProvider(ctx, identitydomain.SSOProvider{}) },
			func(ctx context.Context) error {
				return r.InsertOIDCAuthenticationRequest(ctx, identitydomain.OIDCAuthenticationRequest{}, fixedNow())
			},
			func(ctx context.Context) error {
				_, err := r.ReadOIDCAuthenticationRequest(ctx, "tenant", "provider", "request")
				return err
			},
			func(ctx context.Context) error {
				_, err := r.ConsumeOIDCAuthenticationRequest(ctx, identitydomain.OIDCAuthenticationRequest{}, application.ClockFunc(fixedNow))
				return err
			},
		} {
			// Deliberately verify the repository's nil-context boundary.
			if err := call(nil); !errors.Is(err, ErrValidation) {
				t.Fatal("nil context reached repository state", err)
			}
			if r.uow == nil {
				if err := call(t.Context()); !errors.Is(err, ErrValidation) {
					t.Fatal("nil repository accepted a call", err)
				}
			}
		}
	}
}
