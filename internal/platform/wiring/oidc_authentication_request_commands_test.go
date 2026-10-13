package wiring

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func boundExchangeWiringInput(t *testing.T, store *postgres.Store) identityapp.ExchangeSSOCredentialInput {
	t.Helper()
	begin, err := BuildOIDCAuthenticationRequestCommands(store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	request, state, nonce, err := begin.BeginOIDCAuthentication(t.Context(), identityapp.BeginOIDCAuthenticationInput{ProviderID: "provider"})
	if err != nil || request.ID == "" || state == "" || nonce == "" || request.StateHash != "" || request.NonceHash != "" || request.TrustFingerprint != "" {
		t.Fatal("authentication request did not commit safely", err)
	}
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "exchange-test", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{"iss": "https://issuer.example.test", "aud": "client", "sub": "subject", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce, "groups": []string{"security"}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	return identityapp.ExchangeSSOCredentialInput{ProviderID: "provider", Subject: "subject", IDToken: unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(unsigned))), AuthenticationRequestID: request.ID, StateSecret: state}
}

func signBoundWiringToken(t *testing.T, in identityapp.ExchangeSSOCredentialInput, seed byte, kid string, edit func(map[string]any)) identityapp.ExchangeSSOCredentialInput {
	t.Helper()
	parts := strings.Split(in.IDToken, ".")
	if len(parts) != 3 {
		t.Fatal("invalid signed fixture shape")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(claims)
	}
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	in.IDToken = unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(unsigned)))
	return in
}

func TestPostgresOIDCExchangeRejectsSignedWrongBindingWithoutIssuance(t *testing.T) {
	for _, profile := range []string{"state", "nonce", "old issued-at", "expired state", "foreign provider", "stale trust"} {
		t.Run(profile, func(t *testing.T) {
			store, pool := openHTMLReportWiringStore(t)
			_ = seedSSOExchangeWiring(t, pool)
			in := boundExchangeWiringInput(t, store)
			c, err := BuildSSOExchangeCommands(store, "exchange-test-pepper", false)
			if err != nil {
				t.Fatal(err)
			}
			switch profile {
			case "state":
				in.StateSecret = "evylogin_" + strings.Repeat("A", 43)
			case "nonce":
				in = signBoundWiringToken(t, in, 42, "exchange-test", func(claims map[string]any) { claims["nonce"] = "wrong-signed-nonce" })
			case "old issued-at":
				in = signBoundWiringToken(t, in, 42, "exchange-test", func(claims map[string]any) { claims["iat"] = time.Now().Add(-3 * time.Minute).Unix() })
			case "expired state":
				_, err = pool.Exec(t.Context(), `UPDATE oidc_authentication_requests SET created_at=created_at-interval '6 minutes',expires_at=expires_at-interval '6 minutes' WHERE id=$1`, in.AuthenticationRequestID)
			case "foreign provider":
				_, err = pool.Exec(t.Context(), `INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,groups_claim,role_mapping,status,schema_version,created_at,jwks) SELECT 'foreign-provider','other',name,type,issuer,client_id,groups_claim,role_mapping,status,schema_version,created_at,jwks FROM sso_providers WHERE id='provider'`)
				in.ProviderID = "foreign-provider"
			case "stale trust":
				_, err = pool.Exec(t.Context(), `UPDATE sso_providers SET client_id='rotated-client' WHERE id='provider'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := exchangeWiringCounts(t, pool)
			if v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, identityapp.ErrUnauthorized) || v.ID != "" || session.ID != "" || secret != "" || exchangeWiringCounts(t, pool) != before {
				t.Fatal("wrongly bound signed proof issued authority or effects", err)
			}
			var consumed int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM oidc_authentication_requests WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil || consumed != 0 {
				t.Fatal("invalid binding consumed login state", err)
			}
		})
	}
}

func TestPostgresOIDCExchangeConfiguredKeyRotationSupportsOverlapAndRemoval(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	_ = seedSSOExchangeWiring(t, pool)
	oldRequest := boundExchangeWiringInput(t, store)
	c, err := BuildSSOExchangeCommands(store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	key := func(seed byte, kid string) map[string]any {
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig", "key_ops": []string{"verify"}, "x": base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
	}
	update := func(keys []any) {
		jwks, err := json.Marshal(map[string]any{"keys": keys})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE sso_providers SET jwks=$1 WHERE id='provider'`, jwks); err != nil {
			t.Fatal(err)
		}
	}
	oldKey, newKey := key(42, "exchange-test"), key(43, "rotated")
	update([]any{oldKey, newKey})
	if _, _, secret, err := c.ExchangeSSOCredential(t.Context(), oldRequest); !errors.Is(err, identityapp.ErrUnauthorized) || secret != "" {
		t.Fatal("rotation retained pre-change request authority", err)
	}
	for _, fixture := range []struct {
		seed byte
		kid  string
	}{{42, "exchange-test"}, {43, "rotated"}} {
		in := signBoundWiringToken(t, boundExchangeWiringInput(t, store), fixture.seed, fixture.kid, nil)
		if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), in); err != nil || session.ID == "" || secret == "" {
			t.Fatal("configured overlap key could not issue a fresh bound session", err)
		}
	}
	update([]any{newKey})
	in := boundExchangeWiringInput(t, store)
	if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, identityapp.ErrVerificationFailed) || session.ID != "" || secret != "" {
		t.Fatal("removed key retained session authority", err)
	}
	if counts := exchangeWiringCounts(t, pool); counts[0] != 3 || counts[1] != 2 || counts[3] != 0 {
		t.Fatal("rotation produced partial or replay effects", counts)
	}
}

func TestPostgresOIDCExchangeConcurrentProofIssuesExactlyOneSession(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	_ = seedSSOExchangeWiring(t, pool)
	in := boundExchangeWiringInput(t, store)
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		c, err := BuildSSOExchangeCommands(store, "exchange-test-pepper", false)
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			<-start
			_, _, _, err := c.ExchangeSSOCredential(t.Context(), in)
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, identityapp.ErrUnauthorized) {
			t.Fatal("replay returned an unexpected failure", err)
		}
	}
	var consumed, audited int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM oidc_authentication_requests WHERE consumed_at IS NOT NULL),(SELECT count(*) FROM audit_chain_entries WHERE entry_type='oidc_authentication_request.consumed')`).Scan(&consumed, &audited); err != nil {
		t.Fatal(err)
	}
	if success != 1 || consumed != 1 || audited != 1 || exchangeWiringCounts(t, pool) != [4]int{1, 1, 4, 0} {
		t.Fatal("concurrent proof did not atomically issue exactly once", success, consumed, audited, exchangeWiringCounts(t, pool))
	}
	// A fresh runtime composition must still reject the committed proof.
	restarted, err := BuildSSOExchangeCommands(store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, secret, err := restarted.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, identityapp.ErrUnauthorized) || secret != "" {
		t.Fatal("restart reopened a consumed proof", err)
	}
}

func TestPostgresOIDCExchangeDeferredCommitFailurePreservesRetry(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	_ = seedSSOExchangeWiring(t, pool)
	in := boundExchangeWiringInput(t, store)
	c, err := BuildSSOExchangeCommands(store, "exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_oidc_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic private commit failure'; END$$; CREATE CONSTRAINT TRIGGER reject_oidc_commit AFTER INSERT ON sso_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_oidc_commit()`); err != nil {
		t.Fatal(err)
	}
	before := exchangeWiringCounts(t, pool)
	if v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in); err == nil || v.ID != "" || session.ID != "" || secret != "" || exchangeWiringCounts(t, pool) != before {
		t.Fatal("failed commit delivered credentials or left partial effects", err)
	}
	var consumed int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM oidc_authentication_requests WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil || consumed != 0 {
		t.Fatal("rollback retained consumption", err)
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_oidc_commit ON sso_sessions`); err != nil {
		t.Fatal(err)
	}
	if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), in); err != nil || session.ID == "" || secret == "" || exchangeWiringCounts(t, pool) != [4]int{1, 1, 4, 0} {
		t.Fatal("rolled-back proof could not be safely retried", err)
	}
}
