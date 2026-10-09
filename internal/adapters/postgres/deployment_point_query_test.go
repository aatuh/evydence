package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestPostgresDeploymentPointQueryTenantAndParentConsistency(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_deploy", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, tenantID string }{
		{id: "prod_a", tenantID: "ten_deploy"}, {id: "prod_b", tenantID: "ten_deploy"}, {id: "prod_other", tenantID: "ten_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, item.id, item.tenantID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+item.id, item.tenantID, item.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO deployment_environments (id, tenant_id, product_id, name, kind, schema_version, created_at) VALUES ($1, $2, $3, $1, 'production', 'v1', $4)`, "env_"+item.id, item.tenantID, item.id, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, tenantID, environmentID, releaseID string }{
		{id: "dep_valid", tenantID: "ten_deploy", environmentID: "env_prod_a", releaseID: "rel_prod_a"},
		{id: "dep_mismatch", tenantID: "ten_deploy", environmentID: "env_prod_a", releaseID: "rel_prod_b"},
		{id: "dep_other", tenantID: "ten_other", environmentID: "env_prod_other", releaseID: "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO deployment_events (id, tenant_id, environment_id, release_id, artifact_ids, status, started_at, finished_at, rollback_of, evidence_id, schema_version, created_at) VALUES ($1, $2, $3, $4, ARRAY['art_1'], 'succeeded', $5, $5, NULL, 'ev_1', 'v1', $5)`, item.id, item.tenantID, item.environmentID, item.releaseID, now); err != nil {
			t.Fatal(err)
		}
	}
	point, err := store.GetDeploymentPoint(ctx, "ten_deploy", "dep_valid")
	if err != nil || point.ProductID != "prod_a" || point.Deployment.ID != "dep_valid" || point.Deployment.ReleaseID != "rel_prod_a" || len(point.Deployment.ArtifactIDs) != 1 || point.Deployment.ArtifactIDs[0] != "art_1" || point.Deployment.FinishedAt == nil {
		t.Fatalf("deployment point=%#v error=%v", point, err)
	}
	for _, test := range []struct{ tenantID, id string }{
		{tenantID: "ten_other", id: "dep_valid"},
		{tenantID: "ten_deploy", id: "dep_other"},
		{tenantID: "ten_deploy", id: "dep_mismatch"},
	} {
		if point, err := store.GetDeploymentPoint(ctx, test.tenantID, test.id); !errors.Is(err, operationsquery.ErrNotFound) || point.Deployment.ID != "" {
			t.Fatalf("unsafe deployment point=%#v error=%v", point, err)
		}
	}
	query, err := operationsquery.NewDeploymentPoints(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{
		TenantID: "ten_deploy", UserID: "usr_1", Scopes: []string{"deployment:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"deployment:read"}}},
	}
	if deployment, err := query.GetDeployment(ctx, actor, "dep_valid"); err != nil || deployment.ID != "dep_valid" {
		t.Fatalf("authorized deployment=%#v error=%v", deployment, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_b"
	if deployment, err := query.GetDeployment(ctx, actor, "dep_valid"); !errors.Is(err, application.ErrForbidden) || deployment.ID != "" {
		t.Fatalf("wrong-product deployment=%#v error=%v", deployment, err)
	}
}
