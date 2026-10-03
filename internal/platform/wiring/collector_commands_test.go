package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func TestPostgresCollectorCommandsIssueCompatiblePrivateCredentialsAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Collectors'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildCollectorCommands(store, "collector-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, pepper := range []string{"", " ", identityapp.LocalDevelopmentPepper} {
		if c, err := BuildCollectorCommands(store, pepper, true); !errors.Is(err, identityapp.ErrValidation) || c != nil {
			t.Fatal("unsafe production pepper accepted", err)
		}
	}
	if c, err := BuildCollectorCommands(nil, "collector-test-pepper", true); err == nil || c != nil {
		t.Fatal("missing transactions accepted")
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"collector:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"collector:admin"}}}}
	in := integrationapp.CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1"}
	collector, key, secret, err := commands.CreateCollector(ctx, actor, in)
	if err != nil || collector.ID == "" || key.ID != collector.APIKeyID || key.Hash != "" || secret == "" || !reflect.DeepEqual(key.Scopes, []string{"build:write", "evidence:write"}) {
		t.Fatal("collector credential response violated its contract", err)
	}
	var hash, prefix, actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT hash,prefix FROM api_keys WHERE tenant_id='tenant' AND id=$1`, key.ID).Scan(&hash, &prefix); err != nil {
		t.Fatal(err)
	}
	verifier, err := identityapp.NewHMACAuthenticationCredentials("collector-test-pepper")
	if err != nil || hash != verifier.Hash(secret) || prefix != verifier.Prefix(secret) || prefix != key.Prefix || hash == secret {
		t.Fatal("durable credential is incompatible or exposed", err)
	}
	if err := pool.QueryRow(ctx, `SELECT actor_type,actor_id FROM audit_chain_entries WHERE subject_id=$1`, collector.ID).Scan(&actorType, &actorID); err != nil || actorType != "human_user" || actorID != "human" {
		t.Fatal("human credential issuance not attributed correctly", err)
	}
	authenticator, err := BuildAuthenticator(store, store, "collector-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := authenticator.Authenticate(ctx, secret)
	if err != nil || bound.CollectorID != collector.ID || bound.KeyID != key.ID || bound.TenantID != "tenant" || !reflect.DeepEqual(bound.Scopes, key.Scopes) {
		t.Fatal("committed collector credential did not authenticate with least privilege", err)
	}
	counts := func(want int) {
		t.Helper()
		var keys, collectors, audits int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM api_keys),(SELECT count(*)FROM collectors),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='collector.created')`).Scan(&keys, &collectors, &audits); err != nil || keys != want || collectors != want || audits != want {
			t.Fatal("credential issuance effects were not atomic", keys, collectors, audits, err)
		}
	}
	counts(1)
	if _, _, s, err := commands.CreateCollector(ctx, actor, in); !errors.Is(err, integrationapp.ErrConflict) || s != "" {
		t.Fatal("duplicate name minted or disclosed a credential", err)
	}
	actor.ResourceGrants = nil
	if _, _, s, err := commands.CreateCollector(ctx, actor, in); !errors.Is(err, application.ErrForbidden) || s != "" {
		t.Fatal("removed tenant grant minted or disclosed a credential", err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"collector:admin"}}}
	for _, table := range []string{"api_keys", "collectors", "audit_chain_entries"} {
		if _, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION reject_collector_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private collector storage failure';END$$;CREATE TRIGGER reject_collector_write BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_collector_write()`); err != nil {
			t.Fatal(err)
		}
		request := in
		request.Name = "Failed"
		if c, k, s, err := commands.CreateCollector(ctx, actor, request); err == nil || c.ID != "" || k.ID != "" || s != "" {
			t.Fatal("failed collector write returned partial effects or credential", err)
		} else if p := app.DescribeProblem(err); p.Code != app.CodeInternalError || strings.Contains(p.Detail, "private collector storage failure") {
			t.Fatal("storage failure exposed internal details")
		}
		counts(1)
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_collector_write ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1`, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(ctx, secret); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("revoked collector credential retained authority", err)
	}
}

func TestPostgresCollectorHTTPUsesEmptyLedgerAndPrivateRestartReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"collector:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"collector:admin"}}}}
	auth := &attestationHTTPActor{actor: a}
	request := func(path, key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "collector-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.CollectorCommands == nil {
			t.Fatal("collectors remain Ledger-backed", err)
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private storage") {
			t.Fatal("focused collector HTTP contract changed", path, w.Code, noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("collector error did not use Problem Details")
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
	counts := func() [6]int {
		t.Helper()
		var n [6]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM api_keys),(SELECT count(*)FROM collectors),(SELECT count(*)FROM collector_releases),(SELECT count(*)FROM commercial_collectors),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := `{"name":"Builder","type":"generic_ci","version":"1"}`
	first := request("/v1/collectors", "collector", body, 201)
	secret, ok := first["secret"].(string)
	if !ok || secret == "" {
		t.Fatal("initial collector response omitted its one-time credential")
	}
	before := counts()
	if before != [6]int{1, 1, 0, 0, 1, 1} {
		t.Fatal("collector effects not atomic", before)
	}
	delete(first, "secret")
	if replay := request("/v1/collectors", "collector", body, 201); !reflect.DeepEqual(replay, first) || counts() != before {
		t.Fatal("restart replay changed metadata, exposed secret, or duplicated effects")
	}
	var saved string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='collector'`).Scan(&saved); err != nil || strings.Contains(saved, secret) || strings.Contains(saved, `"secret"`) || strings.Contains(saved, `"hash"`) {
		t.Fatal("durable replay retained private credential data", err)
	}
	request("/v1/collectors", "collector", strings.Replace(body, "Builder", "Changed", 1), 409)
	request("/v1/collectors", "duplicate", body, 409)
	auth.actor.ResourceGrants = nil
	request("/v1/collectors", "collector", body, 403)
	auth.actor = a
	collector := first["collector"].(map[string]any)
	path := "/v1/collectors/" + collector["id"].(string) + "/releases"
	releaseBody := `{"version":"1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sbom_id":"sbom","scan_id":"scan","pinned":true}`
	release := request(path, "release", releaseBody, 201)
	before = counts()
	if replay := request(path, "release", releaseBody, 201); !reflect.DeepEqual(release, replay) || counts() != before {
		t.Fatal("release replay changed")
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET tenant_id='other' WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	request(path, "release", releaseBody, 404)
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	commercialBody := `{"name":"Scanner","provider":"provider","version":"1","manifest_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_scopes":["evidence:write"]}`
	definition := request("/v1/commercial-collectors", "commercial", commercialBody, 201)
	before = counts()
	if before != [6]int{1, 1, 1, 1, 3, 3} {
		t.Fatal("focused collector effects changed", before)
	}
	if replay := request("/v1/commercial-collectors", "commercial", commercialBody, 201); !reflect.DeepEqual(definition, replay) || counts() != before {
		t.Fatal("commercial collector replay changed")
	}
	auth.actor.ResourceGrants = nil
	request("/v1/commercial-collectors", "commercial", commercialBody, 403)
	if counts() != before {
		t.Fatal("current authorization denial mutated effects")
	}
	auth.actor = a
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_collector_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private storage collector failure';END$$`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"api_keys", "collectors", "audit_chain_entries", "idempotency_records", "commit"} {
		table := stage
		trigger := `CREATE TRIGGER reject_collector_http BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_collector_http()`
		if stage == "idempotency_records" {
			trigger = `CREATE TRIGGER reject_collector_http BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN (NEW.state='completed') EXECUTE FUNCTION reject_collector_http()`
		}
		if stage == "commit" {
			table = "collectors"
			trigger = `CREATE CONSTRAINT TRIGGER reject_collector_http AFTER INSERT ON collectors DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_collector_http()`
		}
		if _, err := pool.Exec(ctx, trigger); err != nil {
			t.Fatal(err)
		}
		failedBody := strings.Replace(body, "Builder", "Failure-"+stage, 1)
		request("/v1/collectors", "failure-"+stage, failedBody, 500)
		if counts() != before {
			t.Fatal("outer collector transaction failure leaked effects", stage)
		}
		var unsafeFailed int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE state='failed' AND (response<>'null'::jsonb OR status<>0)`).Scan(&unsafeFailed); err != nil || unsafeFailed != 0 {
			t.Fatal("failed reservation retained a response or secret", err)
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_collector_http ON `+table); err != nil {
			t.Fatal(err)
		}
		if stage == "idempotency_records" || stage == "commit" {
			request("/v1/collectors", "failure-"+stage, failedBody, 201)
			before[0]++
			before[1]++
			before[4]++
			before[5]++
		} else {
			request("/v1/collectors", "failure-"+stage, failedBody, 409)
		}
		if counts() != before {
			t.Fatal("collector failure retry changed effects", stage)
		}
	}
}

func TestPostgresCollectorCommandsValidateBoundedCurrentReferencesAndAtomicPins(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,verification_status,schema_version,created_at)VALUES('sig','tenant','artifact',$1,'Ed25519',repeat('x',9000000),'pending','evydence.signature.v1',now())`, digest)
	exec(`UPDATE sboms SET components=jsonb_build_array(repeat('x',9000000));UPDATE vulnerability_scans SET findings=jsonb_build_array(repeat('x',9000000))`)
	commands, err := BuildCollectorCommands(store, "collector-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"collector:admin"}}
	collector, _, _, err := commands.CreateCollector(ctx, a, integrationapp.CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	in := integrationapp.RecordCollectorReleaseInput{CollectorID: collector.ID, Version: "1", ArtifactDigest: digest, SignatureID: "sig", SBOMID: "sbom", ScanID: "scan", Pinned: true}
	one, err := commands.RecordCollectorRelease(ctx, a, in)
	if err != nil || one.VerificationStatus != "evidence_complete" || one.HealthStatus != "healthy" || len(one.Limitations) != 1 || !one.Pinned {
		t.Fatal("bounded evidence identities were not accepted", err)
	}
	counts := func(want int) {
		t.Helper()
		var releases, audits, pins int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM collector_releases),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='collector_release.recorded'),(SELECT count(*)FROM collector_releases WHERE pinned)`).Scan(&releases, &audits, &pins); err != nil || releases != want || audits != want || pins != 1 {
			t.Fatal("release/pin/audit effects changed", releases, audits, pins, err)
		}
	}
	counts(1)
	for _, tc := range []struct{ change, restore string }{
		{`UPDATE collectors SET tenant_id='other' WHERE id=$1`, `UPDATE collectors SET tenant_id='tenant' WHERE id=$1`},
		{`UPDATE artifact_signatures SET tenant_id='other' WHERE id='sig'`, `UPDATE artifact_signatures SET tenant_id='tenant' WHERE id='sig'`},
		{`UPDATE artifacts SET tenant_id='other' WHERE id='artifact'`, `UPDATE artifacts SET tenant_id='tenant' WHERE id='artifact'`},
		{`UPDATE artifact_signatures SET subject_digest='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' WHERE id='sig'`, `UPDATE artifact_signatures SET subject_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id='sig'`},
		{`UPDATE sboms SET tenant_id='other' WHERE id='sbom'`, `UPDATE sboms SET tenant_id='tenant' WHERE id='sbom'`},
		{`UPDATE vulnerability_scans SET tenant_id='other' WHERE id='scan'`, `UPDATE vulnerability_scans SET tenant_id='tenant' WHERE id='scan'`},
		{`UPDATE evidence_items SET tenant_id='other' WHERE id='ev-sbom'`, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='ev-sbom'`},
		{`UPDATE evidence_items SET tenant_id='other' WHERE id='ev-scan'`, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='ev-scan'`},
		{`UPDATE releases SET product_id='other-product' WHERE id='release'`, `UPDATE releases SET product_id='product' WHERE id='release'`},
		{`UPDATE sboms SET release_id=NULL WHERE id='sbom'`, `UPDATE sboms SET release_id='release' WHERE id='sbom'`},
		{`UPDATE vulnerability_scans SET release_id=NULL WHERE id='scan'`, `UPDATE vulnerability_scans SET release_id='release' WHERE id='scan'`},
	} {
		if strings.Contains(tc.change, "$1") {
			exec(tc.change, collector.ID)
		} else {
			exec(tc.change)
		}
		if err := commands.AuthorizeRecordCollectorRelease(ctx, a, in); !errors.Is(err, integrationapp.ErrNotFound) {
			t.Fatal("stale reference authorized", err)
		}
		if v, err := commands.RecordCollectorRelease(ctx, a, in); !errors.Is(err, integrationapp.ErrNotFound) || v.ID != "" {
			t.Fatal("stale/foreign reference accepted", err)
		}
		counts(1)
		if strings.Contains(tc.restore, "$1") {
			exec(tc.restore, collector.ID)
		} else {
			exec(tc.restore)
		}
	}
	for _, table := range []string{"collector_releases", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_collector_release()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private release storage failure';END$$;CREATE TRIGGER reject_collector_release BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_collector_release()`)
		if v, err := commands.RecordCollectorRelease(ctx, a, in); err == nil || v.ID != "" {
			t.Fatal("failed release committed", err)
		}
		counts(1)
		var pinned bool
		if err := pool.QueryRow(ctx, `SELECT pinned FROM collector_releases WHERE id=$1`, one.ID).Scan(&pinned); err != nil || !pinned {
			t.Fatal("failed new release unpinned original", err)
		}
		exec(`DROP TRIGGER reject_collector_release ON ` + table)
	}
	in.Version = "2"
	two, err := commands.RecordCollectorRelease(ctx, a, in)
	if err != nil || !two.Pinned {
		t.Fatal(err)
	}
	counts(2)
	var oldPinned bool
	if err := pool.QueryRow(ctx, `SELECT pinned FROM collector_releases WHERE id=$1`, one.ID).Scan(&oldPinned); err != nil || oldPinned {
		t.Fatal("new pin did not replace old pin", err)
	}
	commercial := integrationapp.CreateCommercialCollectorInput{Name: " Scanner ", Provider: " provider ", Version: " 1 ", ManifestHash: digest, AllowedScopes: []string{" evidence:write ", "build:read"}}
	v, err := commands.CreateCommercialCollectorDefinition(ctx, a, commercial)
	if err != nil || v.Name != "Scanner" || v.Provider != "provider" || v.Version != "1" || v.Status != "available" || !reflect.DeepEqual(v.AllowedScopes, []string{"build:read", "evidence:write"}) {
		t.Fatal("commercial collector metadata changed", err)
	}
	if err := commands.AuthorizeCreateCommercialCollectorDefinition(ctx, a, commercial); err != nil {
		t.Fatal("existing identity blocked replay guard", err)
	}
	if _, err := commands.CreateCommercialCollectorDefinition(ctx, a, commercial); !errors.Is(err, integrationapp.ErrConflict) {
		t.Fatal("duplicate commercial identity accepted", err)
	}
	var definitions, definitionAudits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM commercial_collectors),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='commercial_collector.created')`).Scan(&definitions, &definitionAudits); err != nil || definitions != 1 || definitionAudits != 1 {
		t.Fatal("commercial identity effects changed", definitions, definitionAudits, err)
	}
}

func TestPostgresCollectorCommandsSerializeConcurrentIssuanceAndPins(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Collectors')`); err != nil {
		t.Fatal(err)
	}
	one, err := BuildCollectorCommands(store, "collector-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildCollectorCommands(store, "collector-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"collector:admin"}}
	type result struct {
		id, keyID, secret string
		err               error
	}
	results := make(chan result, 6)
	for i := 0; i < 6; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, k, s, err := c.CreateCollector(ctx, a, integrationapp.CreateCollectorInput{Name: "Concurrent", Type: "generic_ci", Version: "1"})
			results <- result{v.ID, k.ID, s, err}
		}(i)
	}
	id := ""
	successes := 0
	for i := 0; i < 6; i++ {
		r := <-results
		if r.err == nil {
			successes++
			id = r.id
			if r.id == "" || r.keyID == "" || r.secret == "" {
				t.Error("committed credential response missing data")
			}
		} else if !errors.Is(r.err, integrationapp.ErrConflict) || r.id != "" || r.keyID != "" || r.secret != "" {
			t.Error("conflicting issuance returned partial effects", r.err)
		}
	}
	if successes != 1 {
		t.Fatal("duplicate names issued multiple credentials", successes)
	}
	var keys, collectors, audits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM api_keys),(SELECT count(*)FROM collectors),(SELECT count(*)FROM audit_chain_entries)`).Scan(&keys, &collectors, &audits); err != nil || keys != 1 || collectors != 1 || audits != 1 {
		t.Fatal("concurrent issuance effects changed", keys, collectors, audits, err)
	}
	for i := 0; i < 6; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, err := c.RecordCollectorRelease(ctx, a, integrationapp.RecordCollectorReleaseInput{CollectorID: id, Version: "1", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Pinned: true})
			results <- result{id: v.ID, err: err}
		}(i)
	}
	for i := 0; i < 6; i++ {
		r := <-results
		if r.err != nil || r.id == "" {
			t.Error("concurrent pin command failed", r.err)
		}
	}
	var releases, pins int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM collector_releases),(SELECT count(*)FROM collector_releases WHERE pinned),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='collector_release.recorded')`).Scan(&releases, &pins, &audits); err != nil || releases != 6 || pins != 1 || audits != 6 {
		t.Fatal("concurrent pins not serialized", releases, pins, audits, err)
	}
}
