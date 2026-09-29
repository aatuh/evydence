package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresEvidencePointQueryScopesParentsAndWorkerProjection(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_evidence", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, product := range []struct{ id, tenantID string }{
		{id: "prod_a", tenantID: "ten_evidence"}, {id: "prod_b", tenantID: "ten_evidence"}, {id: "prod_other", tenantID: "ten_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, product.id, product.tenantID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+product.id, product.tenantID, product.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+product.id, product.tenantID, product.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO deployment_environments (id, tenant_id, product_id, name, kind, schema_version, created_at) VALUES ($1, $2, $3, $1, 'production', 'v1', $4)`, "env_"+product.id, product.tenantID, product.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version, created_at) VALUES ($1, $2, $3, $4, 'generic_ci', '0123456789abcdef', 'passed', $5, '[]'::jsonb, 'v1', $5)`, "bld_"+product.id, product.tenantID, "proj_"+product.id, "rel_"+product.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO deployment_events (id, tenant_id, environment_id, release_id, status, started_at, schema_version, created_at) VALUES ($1, $2, $3, $4, 'succeeded', $5, 'v1', $5)`, "dep_"+product.id, product.tenantID, "env_"+product.id, "rel_"+product.id, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, tenantID, productID, projectID, releaseID, buildID, deploymentID, evidenceType string
	}{
		{id: "ev_valid", tenantID: "ten_evidence", productID: "prod_a", projectID: "proj_prod_a", releaseID: "rel_prod_a", buildID: "bld_prod_a", deploymentID: "dep_prod_a", evidenceType: "document"},
		{id: "ev_build_only", tenantID: "ten_evidence", buildID: "bld_prod_a", evidenceType: "document"},
		{id: "ev_deploy_only", tenantID: "ten_evidence", deploymentID: "dep_prod_a", evidenceType: "document"},
		{id: "ev_detached", tenantID: "ten_evidence", evidenceType: "document"},
		{id: "ev_mixed", tenantID: "ten_evidence", productID: "prod_b", projectID: "proj_prod_a", evidenceType: "document"},
		{id: "ev_cross_product", tenantID: "ten_evidence", projectID: "proj_prod_a", releaseID: "rel_prod_b", evidenceType: "document"},
		{id: "ev_cross_build", tenantID: "ten_evidence", buildID: "bld_prod_a", deploymentID: "dep_prod_b", evidenceType: "document"},
		{id: "ev_foreign_build", tenantID: "ten_evidence", buildID: "bld_prod_other", evidenceType: "document"},
		{id: "ev_foreign_deployment", tenantID: "ten_evidence", deploymentID: "dep_prod_other", evidenceType: "document"},
		{id: "ev_missing", tenantID: "ten_evidence", releaseID: "rel_missing", evidenceType: "document"},
		{id: "ev_worker", tenantID: "ten_evidence", releaseID: "rel_prod_a", evidenceType: "parser_normalization"},
		{id: "ev_other", tenantID: "ten_other", productID: "prod_other", evidenceType: "document"},
	} {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO evidence_items (id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
			    type, title, source_system, observed_at, evidence_version, schema_version, payload_hash,
			    canonical_hash, canonicalization, trust_level, verification_status, created_at)
			VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''),
			    $8, 'Evidence point', 'test', $9, 1, 'evidence-item.v1.0.0', 'sha256:payload',
			    'sha256:canonical', 'canonical-json.v1', 'L2', 'pending', $9)`,
			item.id, item.tenantID, item.productID, item.projectID, item.releaseID, item.buildID, item.deploymentID, item.evidenceType, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct{ id, productID, projectID, releaseID string }{
		{id: "ev_valid", productID: "prod_a", projectID: "proj_prod_a", releaseID: "rel_prod_a"},
		{id: "ev_build_only", productID: "prod_a", projectID: "proj_prod_a", releaseID: "rel_prod_a"},
		{id: "ev_deploy_only", productID: "prod_a", releaseID: "rel_prod_a"},
		{id: "ev_detached"},
	} {
		point, err := store.GetEvidencePoint(ctx, "ten_evidence", test.id)
		if err != nil || point.Item.ID != test.id || point.ProductID != test.productID || point.ProjectID != test.projectID || point.ReleaseID != test.releaseID {
			t.Fatalf("evidence point %q=%#v error=%v", test.id, point, err)
		}
	}
	for _, test := range []struct{ tenantID, id string }{
		{tenantID: "ten_other", id: "ev_valid"},
		{tenantID: "ten_evidence", id: "ev_other"},
		{tenantID: "ten_evidence", id: "ev_mixed"},
		{tenantID: "ten_evidence", id: "ev_cross_product"},
		{tenantID: "ten_evidence", id: "ev_cross_build"},
		{tenantID: "ten_evidence", id: "ev_foreign_build"},
		{tenantID: "ten_evidence", id: "ev_foreign_deployment"},
		{tenantID: "ten_evidence", id: "ev_missing"},
	} {
		if point, err := store.GetEvidencePoint(ctx, test.tenantID, test.id); !errors.Is(err, evidencequery.ErrNotFound) || point.Item.ID != "" {
			t.Fatalf("unsafe evidence point=%#v error=%v", point, err)
		}
	}
	if point, err := store.GetEvidencePoint(ctx, "ten_evidence", "ev_worker"); !errors.Is(err, evidencequery.ErrRequiresProjection) || point.Item.ID != "" {
		t.Fatalf("worker-owned evidence point=%#v error=%v", point, err)
	}
	query, err := evidencequery.NewEvidencePoints(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_evidence", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "proj_prod_a", Scopes: []string{"evidence:read"}}}}
	if item, err := query.GetEvidence(ctx, actor, "ev_build_only"); err != nil || item.ID != "ev_build_only" {
		t.Fatalf("project-granted evidence=%#v error=%v", item, err)
	}
	actor.ResourceGrants[0].ResourceID = "proj_prod_b"
	if item, err := query.GetEvidence(ctx, actor, "ev_build_only"); !errors.Is(err, application.ErrForbidden) || item.ID != "" {
		t.Fatalf("wrong-project evidence=%#v error=%v", item, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_prod_a", Scopes: []string{"evidence:read"}}
	if item, err := query.GetEvidence(ctx, actor, "ev_deploy_only"); err != nil || item.ID != "ev_deploy_only" {
		t.Fatalf("release-granted deployment evidence=%#v error=%v", item, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_prod_b"
	if item, err := query.GetEvidence(ctx, actor, "ev_deploy_only"); !errors.Is(err, application.ErrForbidden) || item.ID != "" {
		t.Fatalf("wrong-release deployment evidence=%#v error=%v", item, err)
	}
}
