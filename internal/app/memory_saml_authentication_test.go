package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemorySAMLAuthenticationUsesOwnedStateAndDetachedReplayMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Identity.(interface {
		identityapp.SAMLExchangeReader
		identityapp.SAMLAuthenticationRequestConsumer
		UpsertSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
		InsertSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, time.Time) error
	})
	if !ok {
		t.Fatal("explicit memory UOW lacks narrow SAML operational ports")
	}
	at := fixedNow()
	p := identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "saml", Status: "active", Issuer: "https://idp.example.test", ClientID: "sp", SAMLSigningCertificates: []string{"public fixture metadata"}, CreatedAt: at}
	stored := p
	stored.JWKS = map[string]any{}
	stored.RoleMapping = map[string]string{}
	tx.state.SSOProviders[p.ID] = domain.SSOProvider(stored)
	b := identitydomain.SAMLProviderBinding{TenantID: p.TenantID, ProviderID: p.ID, Provider: p, Recipient: "https://sp.example.test/consume", NameIDFormat: identitydomain.SAMLNameIDUnspecified, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: at}
	if err := r.UpsertSAMLProviderBinding(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	fp, err := identityapp.SAMLProviderTrustFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	request := identitydomain.SAMLAuthenticationRequest{ID: "samlreq_fixture", TenantID: p.TenantID, ProviderID: p.ID, Issuer: p.Issuer, Audience: p.ClientID, Recipient: b.Recipient, NameIDFormat: b.NameIDFormat, Delivery: "api", TrustFingerprint: fp, StateHash: strings.Repeat("a", 64), CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute), SchemaVersion: identitydomain.SAMLAuthenticationRequestSchemaVersion}
	if err := r.InsertSAMLAuthenticationRequest(t.Context(), request, at); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadSAMLAuthenticationRequest(t.Context(), "foreign", p.ID, request.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("memory SAML request crossed tenant ownership", err)
	}
	hash, err := identityapp.SAMLAssertionFingerprint(request, "assertion")
	if err != nil {
		t.Fatal(err)
	}
	proof := identitydomain.SAMLAssertionUse{AssertionHash: hash, IssuedAt: at, ExpiresAt: at.Add(4 * time.Minute)}
	clock := application.ClockFunc(func() time.Time { return at.Add(time.Minute) })
	if _, err := r.ConsumeSAMLAuthenticationRequest(t.Context(), request, proof, clock); err != nil {
		t.Fatal(err)
	}
	got, err := r.ReadSAMLAuthenticationRequest(t.Context(), p.TenantID, p.ID, request.ID)
	if err != nil || got.ConsumedAt == nil {
		t.Fatal("memory SAML did not consume state", err)
	}
	*got.ConsumedAt = at.Add(time.Hour)
	if _, err := r.ConsumeSAMLAuthenticationRequest(t.Context(), request, proof, clock); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("memory SAML replay retained authority", err)
	}
	request.ID = "samlreq_fresh"
	request.StateHash = strings.Repeat("b", 64)
	if err := r.InsertSAMLAuthenticationRequest(t.Context(), request, clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConsumeSAMLAuthenticationRequest(t.Context(), request, proof, clock); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("fresh memory state erased scoped assertion replay", err)
	}
	cloned, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if v := cloned.SAMLAuthenticationRequests[got.ID]; v.ConsumedAt == nil || !v.ConsumedAt.Equal(clock.Now()) {
		t.Fatal("memory transaction clone aliased consumed time")
	}
}
