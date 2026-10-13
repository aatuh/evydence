package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresSAMLSignedReceiptConsumesProofWithoutIssuingSession(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	credentials, err := buildAuthenticationCredentials("exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildProviderVerificationCommands(f.store, nil, credentials)
	if err != nil {
		t.Fatal(err)
	}
	in := identityapp.VerifyProviderIdentityInput{ProviderType: "saml", ProviderID: "provider", Subject: "subject", SAMLAssertion: f.input.SAMLAssertion, AuthenticationRequestID: f.input.AuthenticationRequestID, StateSecret: f.input.StateSecret}
	before := f.counts(t)
	v, err := c.VerifyProviderIdentity(t.Context(), samlBindingWiringActor(), in)
	want := [5]int{before[0] + 1, before[1], before[2] + 2, before[3] + 1, before[4] + 1}
	if err != nil || v.Result != "passed" || v.Profile.ID != "provider-identity-saml-bound.v1" || f.counts(t) != want {
		t.Fatal("standard signed receipt lost proof consumption or issued session authority", err)
	}
	if err := c.AuthorizeVerifyProviderIdentity(t.Context(), samlBindingWiringActor(), in); err != nil {
		t.Fatal("receipt replay guard rejected historical committed state", err)
	}
	if _, err := c.VerifyProviderIdentity(t.Context(), samlBindingWiringActor(), in); !errors.Is(err, identityapp.ErrUnauthorized) || f.counts(t) != want {
		t.Fatal("native receipt reused signed proof", err)
	}
}

func TestPostgresSAMLReceiptCommitFailureRollsBackProofAndKeepsRetrySafe(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	credentials, err := buildAuthenticationCredentials("exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildProviderVerificationCommands(f.store, nil, credentials)
	if err != nil {
		t.Fatal(err)
	}
	in := identityapp.VerifyProviderIdentityInput{ProviderType: "saml", ProviderID: "provider", Subject: "subject", SAMLAssertion: f.input.SAMLAssertion, AuthenticationRequestID: f.input.AuthenticationRequestID, StateSecret: f.input.StateSecret}
	if _, err := f.pool.Exec(t.Context(), `CREATE FUNCTION reject_saml_receipt()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic receipt commit failure';END$$;CREATE CONSTRAINT TRIGGER reject_saml_receipt AFTER INSERT ON provider_verifications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_saml_receipt()`); err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	if v, err := c.VerifyProviderIdentity(t.Context(), samlBindingWiringActor(), in); err == nil || v.ID != "" || f.counts(t) != before {
		t.Fatal("failed receipt commit left proof or verification effects", err)
	}
	if _, err := f.pool.Exec(t.Context(), `DROP TRIGGER reject_saml_receipt ON provider_verifications`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.VerifyProviderIdentity(t.Context(), samlBindingWiringActor(), in); err != nil || v.Result != "passed" || f.counts(t) != [5]int{before[0] + 1, before[1], before[2] + 2, before[3] + 1, before[4] + 1} {
		t.Fatal("rolled-back signed receipt was not retryable", err)
	}
}

func TestPostgresSAMLHTTPReceiptReplayPreservesProofAndRequiresCurrentAdmin(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	credentials, err := buildAuthenticationCredentials("exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	secret := "evysso_" + strings.Repeat("A", 43)
	if _, err := f.pool.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('operator-session','tenant','user','provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, credentials.Prefix(secret), credentials.Hash(secret)); err != nil {
		t.Fatal(err)
	}
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: f.store}, "exchange-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: f.store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return f.store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	canary := newAggregateLoadCanary(t, t.Context(), f.store)
	body, err := json.Marshal(map[string]any{"provider_type": "saml", "provider_id": "provider", "subject": "subject", "saml_assertion": f.input.SAMLAssertion, "authentication_request_id": f.input.AuthenticationRequestID, "state_secret": f.input.StateSecret})
	if err != nil {
		t.Fatal(err)
	}
	post := func(key string, want int) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/provider-verifications", bytes.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || strings.Contains(w.Body.String(), f.input.StateSecret) || strings.Contains(w.Body.String(), f.input.SAMLAssertion) || !canary.Intact(t.Context()) {
			t.Fatal("unsafe or failed native SAML receipt HTTP", w.Code)
		}
		var result struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	before := f.counts(t)
	first := post("saml-receipt", 201)
	if first["result"] != "passed" || f.counts(t) != [5]int{before[0] + 1, before[1], before[2] + 2, before[3] + 1, before[4] + 1} {
		t.Fatal("receipt HTTP lost consumption or issued session")
	}
	before = f.counts(t)
	replay := post("saml-receipt", 201)
	if replay["id"] != first["id"] || f.counts(t) != before {
		t.Fatal("receipt replay reverified proof or added effects")
	}
	post("fresh-saml-receipt", 401)
	if _, err := f.pool.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	post("saml-receipt", 403)
}
