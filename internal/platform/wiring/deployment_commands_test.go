package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestPostgresDeploymentRecordingKeepsEvidenceAuditAndReplayAtomic(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Deployments'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('product2','tenant','Second','second'),('foreign-product','other','Other','other')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state,created_at)VALUES('release','tenant','product','v1',repeat('x',9000000),now()),('release2','tenant','product2','v2','draft',now()),('foreign-release','other','foreign-product','v1','draft',now())`)
	exec(`INSERT INTO deployment_environments(id,tenant_id,product_id,name,kind,schema_version,created_at)VALUES('env','tenant','product','Production',repeat('x',9000000),'deployment-environment.v1.0.0',now()),('env2','tenant','product','Canary','production','deployment-environment.v1.0.0',now()),('foreign-env','other','foreign-product','Other','production','deployment-environment.v1.0.0',now())`)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest,created_at)VALUES('artifact','tenant',repeat('x',9000000),'application/octet-stream',1,'sha256:a',now()),('foreign-artifact','other','Other','application/octet-stream',1,'sha256:b',now())`)
	c, err := BuildDeploymentCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}
	in := operationsapp.RecordDeploymentInput{EnvironmentID: "env", ReleaseID: "release", Status: "succeeded", ArtifactIDs: []string{"artifact", "artifact"}}
	counts := func() [4]int {
		t.Helper()
		var n [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM deployment_events WHERE tenant_id='tenant'),(SELECT count(*)FROM evidence_items WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	v, err := c.RecordDeployment(ctx, a, in)
	if err != nil || v.EvidenceID == "" || counts() != [4]int{1, 1, 2, 0} || !reflect.DeepEqual(v.ArtifactIDs, in.ArtifactIDs) {
		t.Fatal(v, err, counts())
	}
	var dep, evidence, kind, subtype, hash, canonical, entry, status string
	if err := pool.QueryRow(ctx, `SELECT d.id,d.evidence_id,e.type,e.subtype,e.payload_hash,e.canonical_hash,e.chain_entry_id,e.verification_status FROM deployment_events d JOIN evidence_items e ON e.id=d.evidence_id AND e.tenant_id=d.tenant_id WHERE d.id=$1 AND e.deployment_id=d.id`, v.ID).Scan(&dep, &evidence, &kind, &subtype, &hash, &canonical, &entry, &status); err != nil || dep != v.ID || evidence != v.EvidenceID || kind != "deployment" || subtype != "event" || !strings.HasPrefix(hash, "sha256:") || !strings.HasPrefix(canonical, "sha256:") || entry == "" || status != "pending" {
		t.Fatal(dep, evidence, kind, subtype, err)
	}
	point, err := store.GetEvidencePoint(ctx, a.TenantID, v.EvidenceID, func(application.ResourceReferences) error { return nil })
	if err != nil || point.Item.DeploymentID != v.ID || point.Item.ReleaseID != in.ReleaseID || point.Item.CanonicalHash != canonical {
		t.Fatal("evidence not immediately readable", point, err)
	}
	if recomputed, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, point.Item); err != nil || recomputed != canonical {
		t.Fatal("durable evidence commitment changed on round trip", recomputed, canonical, err)
	}
	otherActor := a
	otherActor.TenantID = "other"
	foreign, err := c.RecordDeployment(ctx, otherActor, operationsapp.RecordDeploymentInput{EnvironmentID: "foreign-env", ReleaseID: "foreign-release", Status: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*operationsapp.RecordDeploymentInput){func(in *operationsapp.RecordDeploymentInput) { in.EnvironmentID = "foreign-env" }, func(in *operationsapp.RecordDeploymentInput) { in.ReleaseID = "foreign-release" }, func(in *operationsapp.RecordDeploymentInput) { in.ReleaseID = "release2" }, func(in *operationsapp.RecordDeploymentInput) { in.ArtifactIDs = []string{"foreign-artifact"} }, func(in *operationsapp.RecordDeploymentInput) { in.RollbackOf = "missing" }, func(in *operationsapp.RecordDeploymentInput) { in.RollbackOf = foreign.ID }} {
		request := in
		mutate(&request)
		if v, err := c.RecordDeployment(ctx, a, request); !errors.Is(err, operationsapp.ErrNotFound) || v.ID != "" || counts() != [4]int{1, 1, 2, 0} {
			t.Fatal(v, err, counts())
		}
	}
	for _, failure := range []struct{ table, condition string }{{"evidence_items", ""}, {"audit_chain_entries", ""}, {"audit_chain_entries", " WHEN (NEW.entry_type='deployment.recorded')"}, {"deployment_events", ""}} {
		table := failure.table
		exec(`CREATE OR REPLACE FUNCTION reject_deployment_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected deployment write'; END$$`)
		exec(`CREATE TRIGGER reject_deployment_write BEFORE INSERT ON ` + table + ` FOR EACH ROW` + failure.condition + ` EXECUTE FUNCTION reject_deployment_write()`)
		if v, err := c.RecordDeployment(ctx, a, in); err == nil || v.ID != "" || counts() != [4]int{1, 1, 2, 0} {
			t.Fatal("partial commit", table, v, err, counts())
		}
		exec(`DROP TRIGGER reject_deployment_write ON ` + table)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"deployment:write"}}}}
	rolled := in
	rolled.Status = "rolled_back"
	rolled.RollbackOf = v.ID
	if _, err := c.RecordDeployment(ctx, human, rolled); err != nil {
		t.Fatal("release grant or rollback rejected", err)
	}
	before := counts()
	human.ResourceGrants = nil
	if _, err := c.RecordDeployment(ctx, human, in); !errors.Is(err, application.ErrForbidden) || counts() != before {
		t.Fatal("removed grant retained write access", err)
	}
	otherEnv := rolled
	otherEnv.EnvironmentID = "env2"
	if _, err := c.RecordDeployment(ctx, a, otherEnv); !errors.Is(err, operationsapp.ErrNotFound) || counts() != before {
		t.Fatal("cross-environment rollback accepted", err)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/deployments", "deployment-replay", []byte(`{"status":"succeeded"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			v, err := c.RecordDeployment(ctx, a, in)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counts() != [4]int{before[0] + 1, before[1] + 1, before[2] + 2, 0} {
		t.Fatal("replay duplicated effects", counts())
	}
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/deployments", "deployment-replay", []byte(`{"status":"failed"}`), func(context.Context, app.Repositories) (int, any, error) {
		t.Fatal("different body reached deployment command")
		return 0, nil, nil
	}); !errors.Is(err, app.ErrIdempotencyConflict) {
		t.Fatal("replay accepted changed body", err)
	}
}
