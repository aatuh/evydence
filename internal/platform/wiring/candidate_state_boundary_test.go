package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresCandidateTransitionsSeePendingSnapshotAndRollBackTogether(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Candidate')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildCandidateStateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	rollback := errors.New("rollback candidate transition")
	var snapshot domain.ReleaseCandidate
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			runs++
			at := time.Now().UTC().Truncate(time.Microsecond)
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: "product", TenantID: "tenant", Name: strings.Repeat("x", 9000000), Slug: "product", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: "release", TenantID: "tenant", ProductID: "product", Version: strings.Repeat("v", 65537), State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			snapshot = domain.ReleaseCandidate{ID: "candidate", TenantID: "tenant", ReleaseID: "release", Name: "Snapshot", Revision: 1, State: "open", BuildIDs: []string{"build"}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}, SnapshotHash: "sha256:" + strings.Repeat("c", 64), SchemaVersion: releasedomain.ReleaseCandidateSchemaVersion, CreatedAt: at}
			if err := repos.ReleaseCatalog.InsertReleaseCandidate(txCtx, snapshot); err != nil {
				return 0, nil, err
			}
			v, err := commands.UpdateReleaseCandidateState(txCtx, actor, "candidate", "promoted", "reviewed", 1)
			if err != nil {
				return 0, nil, err
			}
			if v.ID != snapshot.ID || v.TenantID != snapshot.TenantID || v.ReleaseID != snapshot.ReleaseID || v.Name != snapshot.Name || v.SnapshotHash != snapshot.SnapshotHash || v.SchemaVersion != snapshot.SchemaVersion || !v.CreatedAt.Equal(snapshot.CreatedAt) || !reflect.DeepEqual(v.BuildIDs, snapshot.BuildIDs) || !reflect.DeepEqual(v.ArtifactIDs, snapshot.ArtifactIDs) || !reflect.DeepEqual(v.SBOMIDs, snapshot.SBOMIDs) || !reflect.DeepEqual(v.ScanIDs, snapshot.ScanIDs) || !reflect.DeepEqual(v.VEXIDs, snapshot.VEXIDs) || !reflect.DeepEqual(v.ContractIDs, snapshot.ContractIDs) || !reflect.DeepEqual(v.BundleIDs, snapshot.BundleIDs) || v.Revision != 2 || v.State.String() != "promoted" || v.PromotedAt == nil || v.RejectedAt != nil || v.PromotedAt.Nanosecond()%1000 != 0 {
				return 0, nil, errors.New("candidate snapshot or transition changed")
			}
			if fail {
				return 0, nil, rollback
			}
			return 200, v, nil
		}
	}
	counts := func() [4]int {
		t.Helper()
		var n [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM release_candidates),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM products),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-candidate", "rollback", nil, run(true)); !errors.Is(err, rollback) || counts() != [4]int{} {
		t.Fatal("pending candidate rollback failed", err, counts())
	}
	if status, _, err := executor.WithBody(ctx, actor, "POST", "/pending-candidate", "success", nil, run(false)); err != nil || status != 200 || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("candidate effects wrong", status, err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-candidate", "success", nil, run(false)); err != nil || runs != 2 || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("replay repeated transition", err, runs, counts())
	}
}

func TestPostgresCandidateTransitionsBoundReadsAndSerializeRevision(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Transitions'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product',repeat('v',65537),'draft',1);INSERT INTO release_candidates(id,tenant_id,release_id,name,state,snapshot_hash,document,schema_version,revision,created_at)VALUES('candidate','tenant','release','Snapshot','open','sha256:'||repeat('c',64),'{"build_ids":["build"]}','evydence.release-candidate.v1',1,now())`)
	one, err := BuildCandidateStateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildCandidateStateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	foreign := actor
	foreign.TenantID = "other"
	denied := actor
	denied.ResourceGrants = nil
	wrong := actor
	wrong.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "product", Scopes: []string{"release:write"}}}
	for _, tc := range []struct {
		actor identitydomain.Actor
		want  error
	}{{foreign, releaseapp.ErrNotFound}, {denied, application.ErrForbidden}, {wrong, application.ErrForbidden}} {
		if v, err := one.UpdateReleaseCandidateState(ctx, tc.actor, "candidate", "promoted", "reviewed", 9); !errors.Is(err, tc.want) || v.ID != "" {
			t.Fatal("tenant/grant failure", v.ID, err)
		} else if _, ok := releaseapp.CurrentRevision(err); ok {
			t.Fatal("denial exposed revision")
		}
	}
	for _, sql := range []string{`UPDATE release_candidates SET name=repeat('界',22000)`, `UPDATE release_candidates SET document=jsonb_build_object('build_ids',jsonb_build_array(repeat('x',1048577)))`, `UPDATE release_candidates SET document='{"build_ids":[1]}'`, `UPDATE release_candidates SET document='null'`} {
		exec(sql)
		if v, err := one.UpdateReleaseCandidateState(ctx, actor, "candidate", "promoted", "reviewed", 1); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
			t.Fatal("unsupported snapshot accepted", v.ID, err)
		}
		exec(`UPDATE release_candidates SET name='Snapshot',document='{"build_ids":["build"]}'`)
	}
	for _, table := range []string{"release_candidates", "audit_chain_entries"} {
		event := "UPDATE"
		if table == "audit_chain_entries" {
			event = "INSERT"
		}
		exec(`CREATE FUNCTION reject_candidate()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private candidate SQL';END$$;CREATE TRIGGER reject_candidate BEFORE ` + event + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_candidate()`)
		if v, err := one.UpdateReleaseCandidateState(ctx, actor, "candidate", "promoted", "reviewed", 1); err == nil || v.ID != "" {
			t.Fatal("write failure returned candidate", v.ID, err)
		}
		exec(`DROP TRIGGER reject_candidate ON ` + table + `;DROP FUNCTION reject_candidate()`)
		var rev, audits int
		if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*)FROM audit_chain_entries)FROM release_candidates WHERE id='candidate'`).Scan(&rev, &audits); err != nil || rev != 1 || audits != 0 {
			t.Fatal("failure escaped rollback", rev, audits, err)
		}
	}
	type result struct {
		v   releasedomain.ReleaseCandidate
		err error
	}
	results := make(chan result, 8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			<-start
			commands := one
			if i%2 != 0 {
				commands = two
			}
			v, err := commands.UpdateReleaseCandidateState(ctx, actor, "candidate", "promoted", "reviewed", 1)
			results <- result{v, err}
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err == nil && r.v.ID == "candidate" && r.v.Revision == 2 && r.v.State.String() == "promoted" && r.v.PromotedAt != nil && reflect.DeepEqual(r.v.BuildIDs, []string{"build"}) {
			winners++
		} else if rev, ok := releaseapp.CurrentRevision(r.err); !ok || rev != 2 || r.v.ID != "" || !errors.Is(r.err, releaseapp.ErrConflict) {
			t.Fatal("unexpected contender", r.v.ID, r.err, rev, ok)
		}
	}
	var rev, audits int
	if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*)FROM audit_chain_entries)FROM release_candidates WHERE id='candidate'`).Scan(&rev, &audits); err != nil || winners != 1 || rev != 2 || audits != 1 {
		t.Fatal("race duplicated transition/audit", winners, rev, audits, err)
	}
}
