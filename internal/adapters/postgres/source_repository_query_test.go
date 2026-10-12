package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func TestPostgresSourceRepositoryPageFiltersTenantAndCurrentParentBeforeLimit(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_source", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, product := range []struct{ id, tenant string }{
		{id: "prod_a", tenant: "ten_source"}, {id: "prod_b", tenant: "ten_source"}, {id: "prod_other", tenant: "ten_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, product.id, product.tenant, base); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+product.id, product.tenant, product.id, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, repository := range []struct{ id, tenant, project string }{
		{id: "repo_a", tenant: "ten_source", project: "proj_prod_a"},
		{id: "repo_b", tenant: "ten_source", project: "proj_prod_b"},
		{id: "repo_detached", tenant: "ten_source"},
		{id: "repo_foreign_parent", tenant: "ten_source", project: "proj_prod_other"},
		{id: "repo_missing_parent", tenant: "ten_source", project: "proj_missing"},
		{id: "repo_other", tenant: "ten_other", project: "proj_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO source_repositories (id, tenant_id, project_id, provider, full_name, clone_url, default_branch, schema_version, created_at) VALUES ($1, $2, NULLIF($3, ''), 'git', $1, 'https://example.invalid/repo', 'main', 'v1', $4)`, repository.id, repository.tenant, repository.project, base); err != nil {
			t.Fatal(err)
		}
	}
	service, err := integrationquery.NewSourceRepositories(store)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_source", UserID: "usr_1", Scopes: []string{"source:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"source:read"}}}}
	result, err := service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "repo_b" || result.Next != nil {
		t.Fatalf("product-granted repository page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "project", ResourceID: "proj_prod_a", Scopes: []string{"source:read"}}
	result, err = service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "repo_a" || result.Next != nil {
		t.Fatalf("project-granted repository page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_source", Scopes: []string{"source:read"}}
	for _, want := range []string{"repo_a", "repo_b", "repo_detached"} {
		result, err = service.ListPage(ctx, actor, "", page, result.Next)
		if err != nil || len(result.Items) != 1 || result.Items[0].ID != want {
			t.Fatalf("tenant repository page want=%q got=%#v error=%v", want, result, err)
		}
	}
	if result.Next != nil {
		t.Fatalf("unsafe or extra tenant page cursor=%#v", result.Next)
	}
	page.Sort = appquery.SortID
	page.Direction = appquery.Descending
	result, err = service.ListPage(ctx, actor, "proj_prod_b", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "repo_b" {
		t.Fatalf("project-filtered repository page=%#v error=%v", result, err)
	}
	request := integrationquery.SourceRepositoryPageRequest{TenantID: "ten_source", Page: page}
	if _, err := store.PageSourceRepositories(ctx, request); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty grant SQL request error=%v", err)
	}
	request.TenantWide = true
	request.After = &appquery.SortKey{Value: "not-the-id", ID: "repo_a"}
	if _, err := store.PageSourceRepositories(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("noncanonical ID cursor error=%v", err)
	}
	request.Page.Sort = appquery.SortCreatedAt
	request.After = &appquery.SortKey{Value: "not-a-time", ID: "repo_a"}
	if _, err := store.PageSourceRepositories(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed time cursor error=%v", err)
	}
}
