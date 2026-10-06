package wiring

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func seedEvidenceBundleNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	now := time.Now().UTC().Truncate(time.Microsecond)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	for _, q := range []string{
		`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('other-release','tenant','other-product','2','draft'),('foreign-release','other','foreign-product','3','draft')`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,payload_ref)VALUES('selected','tenant','product','project','release','document','private-title','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('excluded','tenant','other-product','other-project','other-release','document','private-title','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('foreign-evidence','other','foreign-product','foreign-project','foreign-release','document','private-title','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload')`,
	} {
		if _, err := p.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider)VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte(private), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresEvidenceBundleNativeConcurrentReplayWritesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	e, ok := o.DurableCommandExecutor.(httpapi.DurableReplayCommandExecutor)
	if !ok {
		t.Fatal("missing replay capability")
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"bundle:read"}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var runs atomic.Int32
	type result struct {
		status int
		value  any
		err    error
	}
	done, start := make(chan result, 2), make(chan struct{})
	for range 2 {
		go func() {
			<-start
			status, value, err := e.WithBodyReplayAuthorization(ctx, a, "POST", "/v1/evidence-bundles", "concurrent", []byte(`{"release_id":"release","evidence_ids":["selected"]}`), func(ctx context.Context) error {
				return o.EvidenceBundleCommands.AuthorizeEvidenceBundleExport(ctx, a, "release", []string{"selected"})
			}, func(ctx context.Context, response any) error {
				root, ok := response.(map[string]any)
				if !ok || root["tenant_id"] != "tenant" || root["release_id"] != "release" {
					return app.ErrConflict
				}
				values, ok := root["evidence_ids"].([]any)
				if !ok || len(values) != 1 || values[0] != "selected" {
					return app.ErrConflict
				}
				return o.EvidenceBundleCommands.AuthorizeEvidenceBundleReplay(ctx, a, "release", []string{"selected"})
			}, func(ctx context.Context) (int, any, error) {
				runs.Add(1)
				v, err := o.EvidenceBundleCommands.ExportEvidenceBundle(ctx, a, "release", []string{"selected"})
				return 201, domain.EvidenceBundle{ID: v.ID, TenantID: v.TenantID, ReleaseID: v.ReleaseID, EvidenceIDs: v.EvidenceIDs, Manifest: v.Manifest, ManifestHash: v.ManifestHash, SignatureRefs: v.SignatureRefs, VerificationText: v.VerificationText, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
			})
			done <- result{status, value, err}
		}()
	}
	close(start)
	var replies [2]string
	for n := range replies {
		select {
		case r := <-done:
			if r.err != nil || r.status != 201 {
				t.Fatal("concurrent export failed", r.status, r.err)
			}
			raw, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[n] = string(raw)
		case <-ctx.Done():
			t.Fatal("concurrent export leaked transaction", ctx.Err())
		}
	}
	assertDeploymentCreationReplay(t, replies[0], replies[1])
	if got := evidenceBundleNativeCounts(t, p); got != [6]int{1, 1, 1, 1, 0, 0} || runs.Load() != 1 {
		t.Fatal("concurrent export duplicated effects", got, runs.Load())
	}
}

type exportNativeProbe struct {
	store        *postgres.Store
	reads, signs int
	fail         bool
}

func (p *exportNativeProbe) ReadEvidenceBundleSnapshot(ctx context.Context, tenant, release string, now time.Time) (packageapp.EvidenceBundleSnapshot, error) {
	p.reads++
	if p.fail {
		return packageapp.EvidenceBundleSnapshot{}, errors.New("private-unexpected-snapshot-read")
	}
	return p.store.ReadEvidenceBundleSnapshot(ctx, tenant, release, now)
}
func (p *exportNativeProbe) SignPackage(ctx context.Context, in packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	p.signs++
	if p.fail {
		return packageapp.PackageSignature{}, errors.New("private-unexpected-signing")
	}
	return p.store.SignPackage(ctx, in)
}

func evidenceBundleNativeHTTP(t *testing.T, store *postgres.Store, probe *exportNativeProbe, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	if probe != nil {
		var err error
		o.EvidenceBundleCommands, err = BuildEvidenceBundleCommands(probe, probe, store)
		if err != nil {
			t.Fatal(err)
		}
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/evidence-bundles", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native export status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("export lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("export lost Problem Details")
	}
	return w.Body.String()
}

func evidenceBundleNativeCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var n [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM evidence_bundles),(SELECT count(*)FROM signatures),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresEvidenceBundleNativeReplayUsesHistoricalSelectionAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	exec := func(q string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='product'WHERE id='grant'`)
	probe := &exportNativeProbe{store: store}
	one := evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 201)
	var e struct {
		Data domain.EvidenceBundle `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || strings.Join(e.Data.EvidenceIDs, ",") != "selected" || e.Data.SchemaVersion != domain.EvidenceBundleSchemaVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 || len(e.Data.SignatureRefs) != 1 {
		t.Fatal("export selection/schema changed", one, err)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	var value, actor, kind, signature string
	if err := p.QueryRow(t.Context(), `SELECT s.value,a.actor_id,a.actor_type,a.signature_ref FROM signatures s JOIN audit_chain_entries a ON a.signature_ref=s.id WHERE s.subject_id=$1`, e.Data.ID).Scan(&value, &actor, &kind, &signature); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(value)
	if err != nil || !ed25519.Verify(public, []byte(e.Data.ManifestHash), decoded) || signature != e.Data.SignatureRefs[0] || actor != "user" || kind != "human_user" {
		t.Fatal("export lost signature or caller attribution", err)
	}
	probe.fail = true
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)SELECT 'newly-selected',tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status FROM evidence_items WHERE id='selected'`)
	exec(`UPDATE evidence_items SET title=repeat('private-',200000),payload_ref=repeat('private-',200000)WHERE id='selected'`)
	exec(`UPDATE signing_keys SET status='revoked',encrypted_private_key=decode(repeat('ab',200000),'hex')WHERE id='key'`)
	assertDeploymentCreationReplay(t, one, evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 201))
	evidenceBundleNativeHTTP(t, store, probe, "original", `{} `, 409)
	for _, g := range []struct{ kind, id string }{{"project", "project"}, {"release", "release"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
			t.Fatal(err)
		}
		assertDeploymentCreationReplay(t, one, evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 201))
	}
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='other-product'WHERE id='grant'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 403)
	exec(`UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 403)
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='product'WHERE id='grant'`)
	exec(`UPDATE evidence_items SET tenant_id='other'WHERE id='selected'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 404)
	exec(`UPDATE evidence_items SET tenant_id='tenant',product_id='other-product',project_id=NULL,release_id=NULL WHERE id='selected'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 403)
	exec(`UPDATE evidence_items SET product_id='product',project_id='project',release_id='release'WHERE id='selected'`)
	assertDeploymentCreationReplay(t, one, evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 201))
	exec(`UPDATE role_bindings SET role='collector'WHERE id='grant'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 403)
	exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant'`)
	exec(`DELETE FROM role_bindings WHERE id='grant'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 403)
	exec(`UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	evidenceBundleNativeHTTP(t, store, probe, "original", `{}`, 401)
	if got := evidenceBundleNativeCounts(t, p); got != [6]int{1, 1, 1, 1, 0, 0} || probe.reads != 1 || probe.signs != 1 {
		t.Fatal("replay reselected/signed or wrote effects", got, probe)
	}
}

func TestPostgresEvidenceBundleNativeRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"signature", "bundle", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedEvidenceBundleNative(t, p)
			body := `{"release_id":"release","evidence_ids":["selected"," selected "]}`
			table := map[string]string{"signature": "signatures", "bundle": "evidence_bundles", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_native_export BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_export()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_native_export BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_export()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_native_export AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_export()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_export()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-export-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			evidenceBundleNativeHTTP(t, store, nil, "failed", body, 500)
			want := [6]int{}
			if stage == "signature" || stage == "bundle" || stage == "audit" {
				want[4] = 1
			}
			if got := evidenceBundleNativeCounts(t, p); got != want {
				t.Fatal("export partially committed", stage, got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_export ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[4] == 1 {
				evidenceBundleNativeHTTP(t, store, nil, key, body, 409)
				key = "recovered"
			}
			one := evidenceBundleNativeHTTP(t, store, nil, key, body, 201)
			assertDeploymentCreationReplay(t, one, evidenceBundleNativeHTTP(t, store, nil, key, body, 201))
			want[0], want[1], want[2], want[3] = 1, 1, 1, 1
			if got := evidenceBundleNativeCounts(t, p); got != want {
				t.Fatal("export recovery duplicated effects", stage, got, want)
			}
		})
	}
}

func TestPostgresEvidenceBundleNativeReleaseRootsRejectForeignOrNarrowSelections(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='project',resource_id='project'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	evidenceBundleNativeHTTP(t, store, nil, "narrow-root", `{"release_id":"release","evidence_ids":["selected"]}`, 403)
	evidenceBundleNativeHTTP(t, store, nil, "foreign", `{"evidence_ids":["foreign-evidence"]}`, 404)
	evidenceBundleNativeHTTP(t, store, nil, "missing", `{"evidence_ids":["missing"]}`, 404)
	evidenceBundleNativeHTTP(t, store, nil, "excluded", `{"evidence_ids":["excluded"]}`, 403)
	if got := evidenceBundleNativeCounts(t, p); got != [6]int{} {
		t.Fatal("denied references reserved keys or wrote effects", got)
	}
	one := evidenceBundleNativeHTTP(t, store, nil, "project", `{"evidence_ids":[" selected ","selected"]}`, 201)
	assertDeploymentCreationReplay(t, one, evidenceBundleNativeHTTP(t, store, nil, "project", `{"evidence_ids":[" selected ","selected"]}`, 201))
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	evidenceBundleNativeHTTP(t, store, nil, "wrong-release", `{"release_id":"release","evidence_ids":["excluded"]}`, 404)
	two := evidenceBundleNativeHTTP(t, store, nil, "product-root", `{"release_id":" release ","evidence_ids":["selected"]}`, 201)
	assertDeploymentCreationReplay(t, two, evidenceBundleNativeHTTP(t, store, nil, "product-root", `{"release_id":" release ","evidence_ids":["selected"]}`, 201))
	if got := evidenceBundleNativeCounts(t, p); got != [6]int{2, 2, 2, 2, 0, 0} {
		t.Fatal("valid narrow grants lost atomic effects", got)
	}
}

func TestPostgresEvidenceBundleNativeReplayKeepsOnlySelectedOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	e, ok := o.DurableCommandExecutor.(httpapi.DurableReplayCommandExecutor)
	if !ok {
		t.Fatal("missing replay executor")
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"bundle:read"}}
	runs, guards := 0, 0
	for range 2 {
		_, _, err := e.WithBodyReplayAuthorization(t.Context(), a, "POST", "/v1/evidence-bundles", "locks", []byte(`{}`), func(ctx context.Context) error {
			return o.EvidenceBundleCommands.AuthorizeEvidenceBundleExport(ctx, a, "", nil)
		}, func(ctx context.Context, _ any) error {
			if err := o.EvidenceBundleCommands.AuthorizeEvidenceBundleReplay(ctx, a, "", []string{"selected"}); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"products", "product", true}, {"projects", "project", true}, {"releases", "release", true}, {"evidence_items", "selected", true}, {"evidence_items", "excluded", false}, {"products", "other-product", false}, {"signing_keys", "key", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("replay lost selected ownership locks or reached signing/unrelated state", tc, err)
				}
			}
			return nil
		}, func(context.Context) (int, any, error) {
			runs++
			return 201, map[string]any{"tenant_id": "tenant", "evidence_ids": []string{"selected"}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if runs != 1 || guards != 1 || evidenceBundleNativeCounts(t, p) != [6]int{0, 0, 0, 1, 0, 0} {
		t.Fatal("replay guard wrote domain effects", runs, guards)
	}
}

func TestPostgresEvidenceBundleCancelledGuardReleasesFenceBeforeOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"bundle:read"}}
	leader, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- o.EvidenceBundleCommands.AuthorizeEvidenceBundleReplay(ctx, a, "release", []string{"selected"})
	}()
	pid := leader.Conn().PgConn().PID()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var waiting bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting)
		return waiting, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM evidence_items WHERE id='selected'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("ownership locks preceded fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guard leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.EvidenceBundleCommands.AuthorizeEvidenceBundleReplay(t.Context(), a, "release", []string{"selected"}); err != nil {
		t.Fatal("cancelled guard leaked fence", err)
	}
	if got := evidenceBundleNativeCounts(t, p); got != [6]int{} {
		t.Fatal("cancelled guard wrote effects", got)
	}
}
