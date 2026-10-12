package wiring

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestPostgresEvidenceBundleExportUsesScopedSnapshotAndAtomicSignature(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Export'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Export','export'),('private','tenant','Private','private'),('foreign','other','Foreign','foreign')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('project','tenant','product','Export')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft')`)
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,payload_ref)
	 VALUES('selected','tenant',NULL,'project','release','document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('excluded','tenant','private',NULL,NULL,'document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('foreign_evidence','other','foreign',NULL,NULL,'document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload')`, now)
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte(private), now.Add(-time.Hour))
	commands, err := BuildEvidenceBundleCommands(store, store, store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"bundle:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"bundle:read"}}}}
	bundle, err := commands.ExportEvidenceBundle(ctx, actor, "", nil)
	if err != nil || strings.Join(bundle.EvidenceIDs, ",") != "selected" {
		t.Fatalf("bundle=%#v err=%v", bundle, err)
	}
	var value, ref string
	if err := pool.QueryRow(ctx, `SELECT s.value,a.signature_ref FROM signatures s JOIN audit_chain_entries a ON a.signature_ref=s.id WHERE s.subject_id=$1`, bundle.ID).Scan(&value, &ref); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || !ed25519.Verify(public, []byte(bundle.ManifestHash), decoded) || ref != bundle.SignatureRefs[0] {
		t.Fatal("signature/audit mismatch", err)
	}
	for _, ids := range [][]string{{"excluded"}, {"foreign_evidence"}, {"missing"}} {
		if _, err := commands.ExportEvidenceBundle(ctx, actor, "", ids); err == nil {
			t.Fatal("unauthorized/missing evidence exported")
		}
	}
	projectActor := actor
	projectActor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: actor.Scopes}}
	if result, err := commands.ExportEvidenceBundle(ctx, projectActor, "", nil); err != nil || strings.Join(result.EvidenceIDs, ",") != "selected" {
		t.Fatal("project grant selection", err)
	}
	if _, err := commands.ExportEvidenceBundle(ctx, projectActor, "release", nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("project grant granted release-root export", err)
	}
	if _, err := commands.ExportEvidenceBundle(ctx, actor, "release", []string{"selected"}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('private_project','tenant','private','Private')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('private_release','tenant','private','2','draft')`)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version,created_at) VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',$1,'[]','build.v1',$1)`, now)
	exec(`INSERT INTO deployment_environments(id,tenant_id,product_id,name,kind,schema_version,created_at) VALUES('environment','tenant','product','Production','production','env.v1',$1)`, now)
	exec(`INSERT INTO deployment_events(id,tenant_id,environment_id,release_id,status,started_at,schema_version,created_at) VALUES('deployment','tenant','environment','release','succeeded',$1,'deployment.v1',$1)`, now)
	exec(`UPDATE evidence_items SET product_id=NULL,project_id=NULL,release_id=NULL,build_id='build',deployment_id='deployment' WHERE id='selected'`)
	snapshot, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", "", now)
	if err != nil || len(snapshot.Evidence) != 2 || snapshot.Evidence[1].ID != "selected" || snapshot.Evidence[1].Resources.ProductID != "product" || snapshot.Evidence[1].Resources.ProjectID != "project" || snapshot.Evidence[1].Resources.ReleaseID != "release" {
		t.Fatalf("inferred coordinates=%#v err=%v", snapshot, err)
	}
	// Locks must hold through commit, not just validate the earlier snapshot.
	locked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(ctx) }()
	locker := repositories.New(locked).Evidence.(exportEvidenceLocker)
	if _, err := locker.LockEvidenceBundleEvidence(ctx, "tenant", "selected"); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{`UPDATE evidence_items SET project_id='private_project' WHERE id='selected'`, `UPDATE projects SET product_id='private' WHERE id='project'`, `UPDATE releases SET product_id='private' WHERE id='release'`, `UPDATE products SET tenant_id='other' WHERE id='product'`, `UPDATE tenants SET name='changed' WHERE id='tenant'`, `UPDATE build_runs SET project_id='private_project' WHERE id='build'`, `UPDATE deployment_events SET release_id='private_release' WHERE id='deployment'`, `UPDATE deployment_environments SET product_id='private' WHERE id='environment'`} {
		writer, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Exec(ctx, `SET LOCAL lock_timeout='20ms'`); err != nil {
			t.Fatal(err)
		}
		_, err = writer.Exec(ctx, mutation)
		_ = writer.Rollback(ctx)
		var lockError *pgconn.PgError
		if !errors.As(err, &lockError) || lockError.Code != "55P03" {
			t.Fatal("scope mutation did not block on commit-time row lock", err)
		}
	}
	if err := locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// Ownership, parent coordinates and signing lifecycle can change after the
	// committed read. Every invalidation must fail before durable writes.
	for _, mutation := range []string{
		`UPDATE evidence_items SET product_id='private',project_id=NULL,release_id=NULL WHERE id='selected'`,
		`UPDATE projects SET product_id='private' WHERE id='project'`,
		`UPDATE releases SET product_id='private' WHERE id='release'`,
		`UPDATE signing_keys SET status='revoked' WHERE id='key'`,
		`UPDATE build_runs SET project_id='private_project' WHERE id='build'`,
		`UPDATE deployment_events SET release_id='private_release' WHERE id='deployment'`,
	} {
		hooked, err := BuildEvidenceBundleCommands(store, bundleSignerHook{store, func() { exec(mutation) }}, store)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := hooked.ExportEvidenceBundle(ctx, actor, "", []string{"selected"}); err == nil || result.ID != "" {
			t.Fatal("stale scope/key committed", err)
		}
		exec(`UPDATE evidence_items SET product_id=NULL,project_id='project',release_id='release' WHERE id='selected'`)
		exec(`UPDATE projects SET product_id='product' WHERE id='project'`)
		exec(`UPDATE releases SET product_id='product' WHERE id='release'`)
		exec(`UPDATE signing_keys SET status='active' WHERE id='key'`)
		exec(`UPDATE build_runs SET project_id='project' WHERE id='build'`)
		exec(`UPDATE deployment_events SET release_id='release' WHERE id='deployment'`)
	}
	invalid, err := BuildEvidenceBundleCommands(store, invalidBundleSigner{store}, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.ExportEvidenceBundle(ctx, actor, "", nil); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal("invalid signature committed", err)
	}
	exec(`UPDATE evidence_items SET product_id='foreign' WHERE id='selected'`)
	if _, err := commands.ExportEvidenceBundle(ctx, actor, "", nil); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal("poisoned references accepted", err)
	}
	exec(`UPDATE evidence_items SET product_id=NULL WHERE id='selected'`)
	exec(`CREATE FUNCTION reject_export_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit failure';END$$`)
	exec(`CREATE TRIGGER reject_export_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_export_audit()`)
	if result, err := commands.ExportEvidenceBundle(ctx, actor, "", nil); err == nil || result.ID != "" {
		t.Fatal("audit failure did not roll back", err)
	}
	var bundles, signatures, audits, jobs int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM evidence_bundles),(SELECT count(*) FROM signatures),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM outbox_jobs)`).Scan(&bundles, &signatures, &audits, &jobs); err != nil || bundles != 3 || signatures != 3 || audits != 3 || jobs != 0 {
		t.Fatalf("partial writes %d/%d/%d/%d err=%v", bundles, signatures, audits, jobs, err)
	}
}
