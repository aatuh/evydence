package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestPostgresDeploymentListsFilterTenantGrantsAndParentsBeforePageLimit(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_list", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, product := range []struct{ id, tenant string }{
		{id: "prod_a", tenant: "ten_list"}, {id: "prod_b", tenant: "ten_list"}, {id: "prod_other", tenant: "ten_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, product.id, product.tenant, base); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+product.id, product.tenant, product.id, base); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO deployment_environments (id, tenant_id, product_id, name, kind, schema_version, created_at) VALUES ($1, $2, $3, $1, 'production', 'v1', $4)`, "env_"+product.id, product.tenant, product.id, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, environment, release string }{
		{id: "dep_a", tenant: "ten_list", environment: "env_prod_a", release: "rel_prod_a"},
		{id: "dep_b", tenant: "ten_list", environment: "env_prod_b", release: "rel_prod_b"},
		{id: "dep_mismatch", tenant: "ten_list", environment: "env_prod_a", release: "rel_prod_b"},
		{id: "dep_other", tenant: "ten_other", environment: "env_prod_other", release: "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO deployment_events (id, tenant_id, environment_id, release_id, artifact_ids, status, started_at, schema_version, created_at) VALUES ($1, $2, $3, $4, ARRAY['art_1'], 'succeeded', $5, 'v1', $5)`, row.id, row.tenant, row.environment, row.release, base); err != nil {
			t.Fatal(err)
		}
	}
	service, err := operationsquery.NewDeploymentLists(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_list", UserID: "usr_1", Scopes: []string{"deployment:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"deployment:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	environments, err := service.ListEnvironmentsPage(ctx, actor, "", page, nil)
	if err != nil || len(environments.Items) != 1 || environments.Items[0].ID != "env_prod_a" || environments.Next != nil {
		t.Fatalf("product-granted environments=%#v error=%v", environments, err)
	}
	deployments, err := service.ListDeploymentsPage(ctx, actor, "", "", page, nil)
	if err != nil || len(deployments.Items) != 1 || deployments.Items[0].ID != "dep_a" || deployments.Next != nil {
		t.Fatalf("product-granted deployments=%#v error=%v", deployments, err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_prod_b", Scopes: []string{"deployment:read"}}}
	deployments, err = service.ListDeploymentsPage(ctx, actor, "", "", page, nil)
	if err != nil || len(deployments.Items) != 1 || deployments.Items[0].ID != "dep_b" || deployments.Next != nil {
		t.Fatalf("release-granted deployments=%#v error=%v", deployments, err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_list", Scopes: []string{"deployment:read"}}}
	environments, err = service.ListEnvironmentsPage(ctx, actor, "", page, nil)
	if err != nil || len(environments.Items) != 1 || environments.Items[0].ID != "env_prod_a" || environments.Next == nil {
		t.Fatalf("tenant first environment page=%#v error=%v", environments, err)
	}
	environments, err = service.ListEnvironmentsPage(ctx, actor, "", page, environments.Next)
	if err != nil || len(environments.Items) != 1 || environments.Items[0].ID != "env_prod_b" || environments.Next != nil {
		t.Fatalf("tenant second environment page=%#v error=%v", environments, err)
	}
	deployments, err = service.ListDeploymentsPage(ctx, actor, "", "", page, nil)
	if err != nil || len(deployments.Items) != 1 || deployments.Items[0].ID != "dep_a" || deployments.Next == nil {
		t.Fatalf("tenant first deployment page=%#v error=%v", deployments, err)
	}
	deployments, err = service.ListDeploymentsPage(ctx, actor, "", "", page, deployments.Next)
	if err != nil || len(deployments.Items) != 1 || deployments.Items[0].ID != "dep_b" || deployments.Next != nil {
		t.Fatalf("tenant second deployment page=%#v error=%v", deployments, err)
	}
	page.Sort = appquery.SortID
	page.Direction = appquery.Descending
	deployments, err = service.ListDeploymentsPage(ctx, actor, "rel_prod_a", "env_prod_a", page, nil)
	if err != nil || len(deployments.Items) != 1 || deployments.Items[0].ID != "dep_a" {
		t.Fatalf("filtered deployment page=%#v error=%v", deployments, err)
	}
	environments, err = service.ListEnvironmentsPage(ctx, actor, "prod_b", page, nil)
	if err != nil || len(environments.Items) != 1 || environments.Items[0].ID != "env_prod_b" {
		t.Fatalf("filtered environment page=%#v error=%v", environments, err)
	}
	request := operationsquery.EnvironmentPageRequest{TenantID: "ten_list", Page: page}
	if _, err := store.PageDeploymentEnvironments(ctx, request); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty grant environment request error=%v", err)
	}
	depRequest := operationsquery.DeploymentPageRequest{TenantID: "ten_list", Page: page}
	if _, err := store.PageDeployments(ctx, depRequest); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty grant deployment request error=%v", err)
	}
	request.TenantWide = true
	request.Page.Sort = appquery.SortCreatedAt
	request.After = &appquery.SortKey{Value: "not-a-time", ID: "env_prod_a"}
	if _, err := store.PageDeploymentEnvironments(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed environment cursor error=%v", err)
	}
	depRequest.TenantWide = true
	depRequest.After = &appquery.SortKey{Value: "wrong-id", ID: "dep_a"}
	if _, err := store.PageDeployments(ctx, depRequest); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed deployment cursor error=%v", err)
	}
}
