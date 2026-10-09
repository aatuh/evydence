package wiring

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

type ssoDiscoveryWiringFake struct {
	requests []app.OIDCDiscoveryRequest
	result   app.OIDCDiscoveryResult
	err      error
}

func (d *ssoDiscoveryWiringFake) FetchOIDCTrustMaterial(_ context.Context, r app.OIDCDiscoveryRequest) (app.OIDCDiscoveryResult, error) {
	d.requests = append(d.requests, r)
	return d.result, d.err
}

func TestPostgresSSOProviderHTTPUsesCurrentAuthorityAndRestartReplayWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if c, err := BuildSSOProviderCommands(nil, nil); err == nil || c != nil {
		t.Fatal("missing provider transactions accepted")
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Providers'),('other','Other');
INSERT INTO products(id,tenant_id,name,slug,created_at)VALUES('product','tenant',repeat('x',9437184),'product',now());
INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES('operator','tenant','operator@example.test','Operator','active','human-user.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Fixture','oidc','https://issuer.example.test','client','active','sso-provider.v1',now()),('unrelated','other',repeat('x',9437184),'oidc','https://other.example.test','client','active','sso-provider.v1',now());
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES('operator-grant','tenant','user','operator','tenant_admin','tenant','tenant','role-binding.v1',now())`)
	credentials, err := identityapp.NewHMACAuthenticationCredentials("provider-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "evysso_provider_fixture"
	exec(`INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('session','tenant','operator','provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, credentials.Prefix(secret), credentials.Hash(secret))
	discovery := &ssoDiscoveryWiringFake{result: app.OIDCDiscoveryResult{Issuer: "https://issuer.example.test/tenant/", JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "discovered", "crv": "Ed25519", "x": "public-only", "client_secret": "private-provider-canary"}}}}}
	request := func(key, body string, want int, route ...string) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, OIDC: discovery}, "provider-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SSOProviderCommands == nil {
			t.Fatal("provider registration remains Ledger-backed", err)
		}
		noReload := newAggregateLoadCanary(t, ctx, store)
		s, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		path := "/v1/sso/providers"
		if len(route) != 0 {
			path = route[0]
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(ctx) || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "private-provider-canary") || len(w.Body.Bytes()) > 32768 {
			t.Fatal("unsafe provider response or Ledger reload", w.Code, noReload.Intact(ctx))
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("provider error lacks Problem Details")
			}
			return nil
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_providers),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records)`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	const body = `{"name":" Example ","type":"oidc","issuer":"https://issuer.example.test/tenant/","client_id":"client","groups_claim":"groups","role_mapping":{"maintainers":"tenant_admin","token-reviewers":"security_engineer","unknown":"future-role"},"jwks":{"client_secret":"private-provider-canary","keys":[{"kty":"OKP","kid":"fixture","crv":"Ed25519","x":"public-only","key_ops":["verify"]}]}}`
	first := request("provider-create", body, 201)
	before := counts()
	if first["name"] != "Example" || first["issuer"] != "https://issuer.example.test/tenant/" || first["tenant_id"] != "tenant" || first["schema_version"] != domain.SSOProviderSchemaVersion {
		t.Fatal("provider DTO contract changed")
	}
	if replay := request("provider-create", body, 201); !reflect.DeepEqual(first, replay) || counts() != before {
		t.Fatal("restart replay changed provider or duplicated effects")
	}
	second := request("provider-create-again", body, 201)
	if first["id"] == second["id"] {
		t.Fatal("new-key duplicate registration was silently reused")
	}
	request("provider-create", strings.Replace(body, " Example ", "Other", 1), 409)
	minimal := `{"name":"Minimal","type":"saml","issuer":"https://saml.example.test/entity","client_id":"client"}`
	if p := request("provider-minimal", minimal, 201); p["type"] != "saml" {
		t.Fatal("optional trust material compatibility lost")
	}
	before = counts()
	for _, bad := range []string{`{}`, `{"tenant_id":"other"}`, strings.Replace(minimal, "https://saml.example.test/entity", "https://user:private-provider-canary@issuer.example.test", 1), strings.Replace(minimal, `"Minimal"`, `"bad\u0000"`, 1), strings.Replace(minimal, `"Minimal"`, `"Minimal","role_mapping":{"g":null}`, 1), strings.Replace(minimal, `"Minimal"`, `"Minimal","jwks":{"keys":[{"kty":"OKP","kid":"bad\u0000","crv":"Ed25519","x":"public-only"}]}`, 1)} {
		request("bad-provider", bad, 400)
	}
	if counts() != before {
		t.Fatal("invalid provider requests emitted effects")
	}
	// Seed the exact receipt shape an older implementation could retain. The
	// new guard must reject the private request even when success already exists.
	authn, err := BuildAuthenticator(store, store, "provider-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := authn.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	privateBody := strings.Replace(body, `"x":"public-only"`, `"x":"public-only","d":"private-provider-canary"`, 1)
	legacy := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := legacy.WithBody(ctx, a, "POST", "/v1/sso/providers", "historical-private", []byte(privateBody), func(context.Context, app.Repositories) (int, any, error) {
		return 201, map[string]any{"jwks": map[string]any{"d": "private-provider-canary"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	before = counts()
	request("historical-private", privateBody, 400)
	if counts() != before {
		t.Fatal("private replay rejection changed retained records")
	}
	for _, query := range []string{`UPDATE role_bindings SET role='collector' WHERE id='operator-grant'`, `UPDATE role_bindings SET role='tenant_admin',resource_type='product',resource_id='product' WHERE id='operator-grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other' WHERE id='operator-grant'`, `UPDATE role_bindings SET tenant_id='other' WHERE id='operator-grant'`} {
		exec(query)
		request("provider-create", body, 403)
		request("unauthorized-new", minimal, 403)
	}
	exec(`UPDATE role_bindings SET tenant_id='tenant',role='tenant_admin',resource_type='tenant',resource_id='tenant' WHERE id='operator-grant';UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='operator'`)
	request("provider-create", body, 401)
	exec(`UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='operator'`)
	if replay := request("provider-create", body, 201); !reflect.DeepEqual(first, replay) || counts() != before {
		t.Fatal("restored current authority changed replay")
	}
	var saved, action, actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='provider-create'`).Scan(&saved); err != nil || strings.Contains(saved, "private-provider-canary") || strings.Contains(saved, secret) {
		t.Fatal("new provider receipt retained secrets", err)
	}
	if err := pool.QueryRow(ctx, `SELECT entry_type,actor_type,actor_id FROM audit_chain_entries WHERE subject_id=$1`, first["id"]).Scan(&action, &actorType, &actorID); err != nil || action != "sso_provider.created" || actorType != "human_user" || actorID != "operator" {
		t.Fatal("provider audit attribution lost", err)
	}
	c, err := BuildSSOProviderCommands(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotationPath := "/v1/sso/providers/" + first["id"].(string) + "/trust-material"
	const trustBody = `{"jwks":{"keys":[{"kty":"OKP","kid":"rotated","crv":"Ed25519","x":"new-public-only"}]}}`
	rotated := request("trust-rotation", trustBody, 200, rotationPath)
	if rotated["id"] != first["id"] || rotated["created_at"] != first["created_at"] || rotated["trust_material_updated_at"] == nil {
		t.Fatal("trust rotation changed immutable provider fields")
	}
	before = counts()
	if replay := request("trust-rotation", trustBody, 200, rotationPath); !reflect.DeepEqual(rotated, replay) || counts() != before {
		t.Fatal("trust restart replay changed DTO or duplicated effects")
	}
	request("foreign-trust", trustBody, 404, "/v1/sso/providers/unrelated/trust-material")
	request("missing-trust", trustBody, 404, "/v1/sso/providers/missing/trust-material")
	request("private-trust", strings.Replace(trustBody, `"x":"new-public-only"`, `"x":"new-public-only","d":"private-provider-canary"`, 1), 400, rotationPath)
	request("trust-rotation", strings.Replace(trustBody, "rotated", "changed", 1), 409, rotationPath)
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='operator-grant'`)
	request("trust-rotation", trustBody, 403, rotationPath)
	exec(`UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='operator-grant'`)
	exec(`UPDATE sso_providers SET tenant_id='other' WHERE id=$1`, first["id"])
	request("trust-rotation", trustBody, 404, rotationPath)
	exec(`UPDATE sso_providers SET tenant_id='tenant',name=repeat('x',9437184) WHERE id=$1`, first["id"])
	request("trust-rotation", trustBody, 409, rotationPath)
	exec(`UPDATE sso_providers SET name='Example' WHERE id=$1`, first["id"])
	for _, malformed := range []struct {
		set     string
		restore any
	}{
		{`role_mapping=jsonb_build_object('oversized',repeat('x',9437184))`, rotated["role_mapping"]},
		{`jwks=jsonb_build_object('oversized',repeat('x',9437184))`, rotated["jwks"]},
		{`saml_signing_certificates=jsonb_build_array(repeat('x',9437184))`, nil},
		{`role_mapping='[]'::jsonb`, rotated["role_mapping"]},
		{`jwks='[]'::jsonb`, rotated["jwks"]},
		{`saml_signing_certificates='{}'::jsonb`, nil},
	} {
		exec(`UPDATE sso_providers SET `+malformed.set+` WHERE id=$1`, first["id"])
		request("trust-rotation", trustBody, 409, rotationPath)
		field, _, _ := strings.Cut(malformed.set, "=")
		encoded, err := json.Marshal(malformed.restore)
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE sso_providers SET `+field+`=$2::jsonb WHERE id=$1`, first["id"], encoded)
		if counts() != before {
			t.Fatal("bounded trust lookup emitted effects", field)
		}
	}
	if replay := request("trust-rotation", trustBody, 200, rotationPath); !reflect.DeepEqual(rotated, replay) || counts() != before {
		t.Fatal("trust guards mutated saved provider/receipt")
	}
	discoveryPath := "/v1/sso/providers/" + first["id"].(string) + "/discover-oidc"
	refreshed := request("provider-discovery", `{}`, 200, discoveryPath)
	if len(discovery.requests) != 1 || discovery.requests[0] != (app.OIDCDiscoveryRequest{TenantID: "tenant", ProviderID: first["id"].(string), Issuer: first["issuer"].(string)}) || refreshed["created_at"] != first["created_at"] || refreshed["trust_material_updated_at"] == nil {
		t.Fatal("discovery composition lost current provider identity")
	}
	before = counts()
	discovery.err = errors.New("private-provider-canary")
	if replay := request("provider-discovery", `{}`, 200, discoveryPath); !reflect.DeepEqual(refreshed, replay) || counts() != before || len(discovery.requests) != 1 {
		t.Fatal("discovery replay fetched keys or changed public DTO")
	}
	request("provider-discovery", "", 409, discoveryPath)
	for _, body := range []string{"null", "[]", `{} {}`, `{"extra":true}`} {
		request("malformed-discovery", body, 400, discoveryPath)
	}
	request("foreign-discovery", `{}`, 404, "/v1/sso/providers/unrelated/discover-oidc")
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='operator-grant'`)
	request("provider-discovery", `{}`, 403, discoveryPath)
	exec(`UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='operator-grant'`)
	exec(`UPDATE role_bindings SET role='collector' WHERE id='operator-grant'`)
	request("provider-discovery", `{}`, 403, discoveryPath)
	exec(`UPDATE role_bindings SET role='tenant_admin' WHERE id='operator-grant';UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='operator'`)
	request("provider-discovery", `{}`, 401, discoveryPath)
	exec(`UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='operator'`)
	exec(`UPDATE sso_providers SET type='saml' WHERE id=$1`, first["id"])
	request("provider-discovery", `{}`, 400, discoveryPath)
	exec(`UPDATE sso_providers SET type='oidc',tenant_id='other' WHERE id=$1`, first["id"])
	request("provider-discovery", `{}`, 404, discoveryPath)
	exec(`UPDATE sso_providers SET tenant_id='tenant',name=repeat('x',9437184) WHERE id=$1`, first["id"])
	request("provider-discovery", `{}`, 409, discoveryPath)
	exec(`UPDATE sso_providers SET name='Example' WHERE id=$1`, first["id"])
	if counts() != before || len(discovery.requests) != 1 {
		t.Fatal("discovery guards fetched metadata or reserved retries")
	}
	request("unavailable-discovery", `{}`, 422, discoveryPath)
	if after := counts(); after[0] != before[0] || after[1] != before[1] || after[2] != before[2]+1 || len(discovery.requests) != 2 {
		t.Fatal("failed discovery changed providers or audit")
	}
	var failureState, failureBody string
	var failureStatus int
	if err := pool.QueryRow(ctx, `SELECT state,response::text,status FROM idempotency_records WHERE idempotency_key='unavailable-discovery'`).Scan(&failureState, &failureBody, &failureStatus); err != nil || failureState != "failed" || failureBody != "null" || failureStatus != 0 {
		t.Fatal("failed discovery retained a partial result or provider error", err)
	}
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='provider-discovery'`).Scan(&saved); err != nil || strings.Contains(saved, "private-provider-canary") {
		t.Fatal("discovery receipt retained provider extensions", err)
	}
	before = counts()
	a = domain.Actor{TenantID: "missing", KeyID: "key", Scopes: []string{"identity:admin"}}
	if out, err := c.CreateSSOProvider(ctx, a, identityapp.CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client"}); !errors.Is(err, identityapp.ErrNotFound) || out.ID != "" || counts() != before {
		t.Fatal("missing tenant provider creation produced effects", err)
	}
}

func TestPostgresSSOTrustSAMLRetainsOnlyPublicCertificatesAndReplays(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','SAML rotation')`); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "saml.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOProviderCommands(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	p, err := c.CreateSSOProvider(ctx, a, identityapp.CreateSSOProviderInput{Name: "Fixture", Type: "saml", Issuer: "https://saml.example.test/entity", ClientID: "client", RoleMapping: map[string]string{"token-reviewers": "security_engineer"}})
	if err != nil {
		t.Fatal(err)
	}
	in := identityapp.UpdateSSOProviderTrustMaterialInput{SAMLSigningCertificates: []string{" \n" + certificate + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeUpdateSSOProviderTrustMaterial(ctx, a, p.ID, in)
	}}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.UpdateSSOProviderTrustMaterial(ctx, a, p.ID, in)
		if err == nil && (v.ID != p.ID || !v.CreatedAt.Equal(p.CreatedAt) || v.JWKS != nil || v.TrustMaterialUpdatedAt == nil || !reflect.DeepEqual(v.SAMLSigningCertificates, []string{certificate})) {
			return 0, nil, errors.New("SAML rotation changed public provider contract")
		}
		return 200, domain.SSOProvider(v), err
	}
	path := "/v1/sso/providers/" + p.ID + "/trust-material"
	status, first, err := executor.WithBody(ctx, a, "POST", path, "saml-rotation", []byte(`{}`), run)
	if err != nil || status != 200 {
		t.Fatal("SAML public rotation failed", err)
	}
	status, replay, err := executor.WithBody(ctx, a, "POST", path, "saml-rotation", []byte(`{}`), run)
	firstJSON, firstErr := json.Marshal(first)
	replayJSON, replayErr := json.Marshal(replay)
	var firstDTO, replayDTO map[string]any
	if firstErr != nil || replayErr != nil || json.Unmarshal(firstJSON, &firstDTO) != nil || json.Unmarshal(replayJSON, &replayDTO) != nil {
		t.Fatal("SAML rotation response is not public JSON")
	}
	if err != nil || status != 200 || !reflect.DeepEqual(firstDTO, replayDTO) {
		t.Fatal("SAML rotation changed replay", err)
	}
	var stored, saved, payloadHash string
	var audits int
	if err := pool.QueryRow(ctx, `SELECT saml_signing_certificates::text,(SELECT response::text FROM idempotency_records WHERE idempotency_key='saml-rotation'),(SELECT payload_hash FROM audit_chain_entries WHERE entry_type='sso_provider.trust_material_updated'),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='sso_provider.trust_material_updated') FROM sso_providers WHERE id=$1`, p.ID).Scan(&stored, &saved, &payloadHash, &audits); err != nil || audits != 1 || !strings.HasPrefix(payloadHash, "sha256:") || strings.Contains(stored+saved, "PRIVATE KEY") {
		t.Fatal("SAML public persistence leaked private PEM or duplicated audit", err)
	}
	var certificates []string
	if err := json.Unmarshal([]byte(stored), &certificates); err != nil || !reflect.DeepEqual(certificates, []string{certificate}) {
		t.Fatal("SAML persistence changed normalized certificate", err)
	}
}

func TestPostgresSSOTrustWriteAuditReplayAndDeferredCommitFailuresRollBack(t *testing.T) {
	for _, mode := range []string{"manual", "discovery"} {
		t.Run(mode, func(t *testing.T) { testPostgresSSOTrustRollback(t, mode) })
	}
}

func testPostgresSSOTrustRollback(t *testing.T, mode string) {
	t.Helper()
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Trust rotation')`); err != nil {
		t.Fatal(err)
	}
	discovery := &ssoDiscoveryWiringFake{result: app.OIDCDiscoveryResult{Issuer: "https://issuer.example.test", JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "discovered", "crv": "Ed25519", "x": "public-only"}}}}}
	c, err := BuildSSOProviderCommands(store, discovery)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	p, err := c.CreateSSOProvider(ctx, a, identityapp.CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	in := identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "rotated", "crv": "Ed25519", "x": "public-only"}}}}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		if mode == "discovery" {
			return c.AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx, a, p.ID)
		}
		return c.AuthorizeUpdateSSOProviderTrustMaterial(ctx, a, p.ID, in)
	}}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		if mode == "discovery" {
			v, err := c.RefreshSSOProviderOIDCTrustMaterial(ctx, a, p.ID)
			return 200, domain.SSOProvider(v), err
		}
		v, err := c.UpdateSSOProviderTrustMaterial(ctx, a, p.ID, in)
		return 200, domain.SSOProvider(v), err
	}
	path := "/v1/sso/providers/" + p.ID + "/trust-material"
	if mode == "discovery" {
		path = "/v1/sso/providers/" + p.ID + "/discover-oidc"
	}
	snapshot := func() (string, [2]int) {
		t.Helper()
		var trust string
		var counts [2]int
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_object('jwks',jwks,'certificates',saml_signing_certificates,'updated_at',trust_material_updated_at)::text,(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed') FROM sso_providers WHERE id=$1`, p.ID).Scan(&trust, &counts[0], &counts[1]); err != nil {
			t.Fatal(err)
		}
		return trust, counts
	}
	for _, stage := range []string{"sso_providers", "audit_chain_entries", "replay", "commit"} {
		var setup, teardown string
		switch stage {
		case "replay":
			setup = `CREATE OR REPLACE FUNCTION reject_trust_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private trust storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_trust_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_trust_stage()`
			teardown = `DROP TRIGGER reject_trust_stage ON idempotency_records`
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_trust_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private trust storage';END$$;CREATE CONSTRAINT TRIGGER reject_trust_stage AFTER UPDATE ON sso_providers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_trust_stage()`
			teardown = `DROP TRIGGER reject_trust_stage ON sso_providers`
		default:
			operation := "INSERT"
			if stage == "sso_providers" {
				operation = "UPDATE"
			}
			setup = `CREATE OR REPLACE FUNCTION reject_trust_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private trust storage';END$$;CREATE TRIGGER reject_trust_stage BEFORE ` + operation + ` ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_trust_stage()`
			teardown = `DROP TRIGGER reject_trust_stage ON ` + stage
		}
		beforeTrust, before := snapshot()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, a, "POST", path, stage, []byte(`{}`), run); err == nil {
			t.Fatal("trust fault did not fail", stage)
		}
		if trust, counts := snapshot(); trust != beforeTrust || counts != before {
			t.Fatal("trust failure committed partial update, audit, or replay", stage)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed trust rotation retained success", stage, err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		status, response, err := executor.WithBody(ctx, a, "POST", path, stage, []byte(`{}`), run)
		if stage == "replay" || stage == "commit" {
			if err != nil || status != 200 || response == nil {
				t.Fatal("rolled back trust rotation cannot retry", stage, err)
			}
			before[0]++
			before[1]++
			committed, _ := snapshot()
			if _, _, err := executor.WithBody(ctx, a, "POST", path, stage, []byte(`{}`), run); err != nil {
				t.Fatal("trust retry cannot replay", stage, err)
			}
			if trust, counts := snapshot(); trust != committed || counts != before {
				t.Fatal("trust retry duplicated effects", stage)
			}
		} else if !errors.Is(err, app.ErrIdempotencyFailed) {
			t.Fatal("failed trust reservation unexpectedly retried", stage, err)
		}
	}
}

func TestPostgresSSOProviderWriteAuditReplayAndDeferredCommitFailuresRollBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Providers')`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOProviderCommands(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	in := identityapp.CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client"}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeCreateSSOProvider(ctx, a, in) }}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateSSOProvider(ctx, a, in)
		return 201, domain.SSOProvider(v), err
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_providers),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, stage := range []string{"sso_providers", "audit_chain_entries", "replay", "commit"} {
		var setup, teardown string
		switch stage {
		case "replay":
			setup = `CREATE OR REPLACE FUNCTION reject_provider_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private provider storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_provider_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_provider_stage()`
			teardown = `DROP TRIGGER reject_provider_stage ON idempotency_records`
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_provider_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private provider storage';END$$;CREATE CONSTRAINT TRIGGER reject_provider_stage AFTER INSERT ON sso_providers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_provider_stage()`
			teardown = `DROP TRIGGER reject_provider_stage ON sso_providers`
		default:
			setup = `CREATE OR REPLACE FUNCTION reject_provider_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private provider storage';END$$;CREATE TRIGGER reject_provider_stage BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_provider_stage()`
			teardown = `DROP TRIGGER reject_provider_stage ON ` + stage
		}
		before := counts()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/providers", stage, []byte(`{}`), run); err == nil || counts() != before {
			t.Fatal("provider failure left committed effects", stage, err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed provider write retained success", stage, err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		status, response, err := executor.WithBody(ctx, a, "POST", "/v1/sso/providers", stage, []byte(`{}`), run)
		if stage == "replay" || stage == "commit" {
			if err != nil || status != 201 || response == nil {
				t.Fatal("rolled back provider reservation cannot retry", stage, err)
			}
			for i := range before {
				before[i]++
			}
			if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/providers", stage, []byte(`{}`), run); err != nil {
				t.Fatal("provider retry cannot replay", stage, err)
			}
		} else if !errors.Is(err, app.ErrIdempotencyFailed) {
			t.Fatal("failed provider reservation unexpectedly retried", stage, err)
		}
		if counts() != before {
			t.Fatal("provider retry duplicated effects", stage)
		}
	}
}
