package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresBuildAttestationReaderBoundsAndLocksOneSnapshot(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Build'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('second','tenant','Second','second'),('foreign','other','Foreign','foreign')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('foreign','other','foreign','Foreign'),('tainted','tenant','foreign','Tainted')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('second','tenant','second','2','draft'),('foreign','other','foreign','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	when := time.Date(2026, 10, 2, 10, 0, 0, 123456000, time.FixedZone("EEST", 10800))
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,repository,workflow_ref,run_id,run_attempt,job_id,actor,ref,oidc_subject,status,started_at,finished_at,parameters_hash,environment_hash,source_identity,outputs,schema_version,created_at)VALUES('build','tenant','project','release','generic_ci','sha','org/repo','workflow','run',2,'job','actor','ref','subject','passed',$1,$1,'parameters','environment','{"source":"api","oidc_verified":false}',jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest',$2::text)),'v1',$1)`, when, digest)
	value, err := store.ReadBuildAttestationBuild(ctx, "tenant", "build")
	utc := when.UTC()
	want := releasedomain.BuildRun{
		ID: "build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: "sha",
		Repository: "org/repo", WorkflowRef: "workflow", RunID: "run", RunAttempt: 2, JobID: "job", Actor: "actor", Ref: "ref", OIDCSubject: "subject",
		Status: "passed", StartedAt: utc, FinishedAt: &utc, ParametersHash: "parameters", EnvironmentHash: "environment",
		SourceIdentity: map[string]any{"source": "api", "oidc_verified": false}, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: digest}},
		SchemaVersion: "v1", CreatedAt: utc,
	}
	if err != nil || !reflect.DeepEqual(value, want) {
		t.Fatalf("snapshot=%#v want=%#v err=%v", value, want, err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Builds.(releaseapp.BuildAttestationSnapshotReader)
		if !ok {
			t.Fatal("build repository lacks focused snapshot port")
		}
		locked, err := reader.ReadBuildAttestationBuild(ctx, "tenant", "build")
		if err != nil || !reflect.DeepEqual(locked, value) {
			t.Fatalf("locked=%#v want=%#v err=%v", locked, value, err)
		}
		// NOWAIT proves the selected build and all authorization parents remain
		// locked by this transaction, without sleeps or scheduler assumptions.
		for _, sql := range []string{`SELECT id FROM build_runs WHERE id='build' FOR UPDATE NOWAIT`, `SELECT id FROM projects WHERE id='project' FOR UPDATE NOWAIT`, `SELECT id FROM releases WHERE id='release' FOR UPDATE NOWAIT`, `SELECT id FROM products WHERE id='product' FOR UPDATE NOWAIT`} {
			var id string
			var pgErr *pgconn.PgError
			if err := pool.QueryRow(ctx, sql).Scan(&id); !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("snapshot row was not share-locked: %s err=%v", sql, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"missing", " "} {
		if v, err := store.ReadBuildAttestationBuild(ctx, "tenant", id); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, releasedomain.BuildRun{}) {
			t.Fatal("missing snapshot", v, err)
		}
	}
	if v, err := store.ReadBuildAttestationBuild(ctx, "other", "build"); !errors.Is(err, app.ErrNotFound) || v.ID != "" {
		t.Fatal("foreign snapshot", v, err)
	}
	for _, id := range []string{"bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if v, err := store.ReadBuildAttestationBuild(ctx, "tenant", id); !errors.Is(err, app.ErrValidation) || v.ID != "" {
			t.Fatal("invalid ID reached SQL", v, err)
		}
	}
	for _, change := range []string{`project_id='foreign'`, `project_id='tainted'`, `release_id='second'`, `release_id='foreign'`} {
		exec(`UPDATE build_runs SET ` + change + ` WHERE id='build'`)
		if v, err := store.ReadBuildAttestationBuild(ctx, "tenant", "build"); !errors.Is(err, app.ErrNotFound) || v.ID != "" {
			t.Fatal("bad parents accepted", change, v, err)
		}
		exec(`UPDATE build_runs SET project_id='project',release_id='release' WHERE id='build'`)
	}
	for _, change := range []string{`source_identity=jsonb_build_object('large',repeat('x',1048576))`, `outputs=jsonb_build_array(jsonb_build_object('digest',repeat('x',1048576)))`, `repository=repeat('x',65537)`, `provider=repeat('x',1025)`, `outputs='{}'::jsonb`, `outputs='null'::jsonb`, `source_identity='[]'::jsonb`} {
		exec(`UPDATE build_runs SET ` + change + ` WHERE id='build'`)
		if v, err := store.ReadBuildAttestationBuild(ctx, "tenant", "build"); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, releasedomain.BuildRun{}) {
			t.Fatal("oversized/malformed stored snapshot returned", change, v, err)
		}
		exec(`UPDATE build_runs SET source_identity='{}',outputs='[]',repository='org/repo',provider='generic_ci'WHERE id='build'`)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ReadBuildAttestationBuild(cancelled, "tenant", "build"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read", err)
	}
}
