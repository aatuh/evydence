package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestPostgresBuildPointQueryTenantAndParentConsistency(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_build", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, tenantID string
	}{
		{id: "prod_build_a", tenantID: "ten_build"},
		{id: "prod_build_b", tenantID: "ten_build"},
		{id: "prod_other", tenantID: "ten_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, item.id, item.tenantID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+item.id, item.tenantID, item.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, $1, 'draft', $4)`, "rel_"+item.id, item.tenantID, item.id, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, tenantID, projectID, releaseID string
	}{
		{id: "bld_valid", tenantID: "ten_build", projectID: "proj_prod_build_a", releaseID: "rel_prod_build_a"},
		{id: "bld_mismatch", tenantID: "ten_build", projectID: "proj_prod_build_a", releaseID: "rel_prod_build_b"},
		{id: "bld_other", tenantID: "ten_other", projectID: "proj_prod_other", releaseID: "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha,
			       repository, workflow_ref, run_id, run_attempt, job_id, actor, ref, oidc_subject,
			       status, started_at, parameters_hash, environment_hash, source_identity,
			       outputs, schema_version, created_at)
			VALUES ($1, $2, $3, $4, 'github', '0123456789abcdef',
			       'org/repo', 'ci.yml', $1, 2, 'job-1', 'ci-bot', 'refs/heads/main', 'repo:org/repo:ref:main',
			       'completed', $5, 'sha256:parameters', 'sha256:environment', '{"issuer":"test"}',
			       '[{"artifact_id":"art_1","digest":"sha256:output"}]', 'v1', $5)`,
			item.id, item.tenantID, item.projectID, item.releaseID, now); err != nil {
			t.Fatal(err)
		}
	}
	point, err := store.GetBuildPoint(ctx, "ten_build", "bld_valid")
	if err != nil || point.ProductID != "prod_build_a" || point.Build.ID != "bld_valid" || point.Build.ProjectID != "proj_prod_build_a" || point.Build.ReleaseID != "rel_prod_build_a" || point.Build.RunAttempt != 2 || point.Build.OIDCSubject != "repo:org/repo:ref:main" || point.Build.SourceIdentity["issuer"] != "test" || len(point.Build.Outputs) != 1 || point.Build.Outputs[0].ArtifactID != "art_1" {
		t.Fatalf("build point=%#v error=%v", point, err)
	}
	for _, test := range []struct {
		tenantID, id string
	}{
		{tenantID: "ten_other", id: "bld_valid"},
		{tenantID: "ten_build", id: "bld_other"},
		{tenantID: "ten_build", id: "bld_mismatch"},
	} {
		if point, err := store.GetBuildPoint(ctx, test.tenantID, test.id); !errors.Is(err, releasequery.ErrNotFound) || point.Build.ID != "" {
			t.Fatalf("unsafe build point=%#v error=%v", point, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE build_runs SET outputs = '{}'::jsonb WHERE id = 'bld_valid'`); err != nil {
		t.Fatal(err)
	}
	if point, err := store.GetBuildPoint(ctx, "ten_build", "bld_valid"); err == nil || point.Build.ID != "" || strings.Contains(err.Error(), "artifact_id") {
		t.Fatalf("malformed build output point=%#v error=%v", point, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE build_runs SET outputs = '[]'::jsonb, source_identity = jsonb_build_object('oversized', $1::text) WHERE id = 'bld_valid'`, strings.Repeat("x", maxBuildPointJSONBytes)); err != nil {
		t.Fatal(err)
	}
	if point, err := store.GetBuildPoint(ctx, "ten_build", "bld_valid"); err == nil || point.Build.ID != "" {
		t.Fatalf("oversized build metadata point=%#v error=%v", point, err)
	}
}
