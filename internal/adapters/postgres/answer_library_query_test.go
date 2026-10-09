package postgres

import (
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestPostgresAnswerLibraryPageFiltersGrantAndParentsBeforeLimit(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_drafts", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ product, tenant string }{{"prod_a", "ten_drafts"}, {"prod_b", "ten_drafts"}, {"prod_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, parent.product, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO control_frameworks (id, tenant_id, name, slug, version, status, schema_version, created_at) VALUES ('fw_other', 'ten_other', 'Other', 'other', '1', 'active', 'control-framework.v1.0.0', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO security_controls (id, tenant_id, framework_id, code, title, objective, evidence_requirements, applicability, limitations, schema_version, created_at) VALUES ('ctrl_other', 'ten_other', 'fw_other', 'X', 'Other', 'Other', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'security-control.v1.0.0', $1)`, now); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, tenant, product, release string }{
		{"draft_a", "ten_drafts", "prod_a", ""},
		{"draft_b", "ten_drafts", "prod_b", ""},
		{"draft_global", "ten_drafts", "", ""},
		{"draft_release", "ten_drafts", "", "rel_prod_a"},
		{"draft_cross_parent", "ten_drafts", "prod_a", "rel_prod_b"},
		{"draft_foreign_parent", "ten_drafts", "prod_other", ""},
		{"draft_foreign_control", "ten_drafts", "prod_a", ""},
		{"draft_dangling_evidence", "ten_drafts", "prod_a", ""},
		{"draft_other", "ten_other", "prod_other", ""},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO questionnaire_answer_library (id, tenant_id, question_id, product_id, release_id, answer, schema_version, created_at) VALUES ($1, $2, 'q1', NULLIF($3, ''), NULLIF($4, ''), $1, 'questionnaire-answer-library.v1.0.0', $5)`, row.id, row.tenant, row.product, row.release, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE questionnaire_answer_library SET control_id = 'ctrl_other' WHERE id = 'draft_foreign_control'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE questionnaire_answer_library SET evidence_ids = ARRAY['ev_missing'] WHERE id = 'draft_dangling_evidence'`); err != nil {
		t.Fatal(err)
	}
	service, err := packagequery.NewAnswerLibrary(store)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_drafts", UserID: "usr_1", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"package:read"}}}}
	first, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{}, page, nil)
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != "draft_a" || first.Next == nil {
		t.Fatalf("first product page=%#v error=%v", first, err)
	}
	second, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{}, page, first.Next)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "draft_release" || second.Next != nil {
		t.Fatalf("second product page=%#v error=%v", second, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_prod_a", Scopes: []string{"package:read"}}
	releasePage, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{}, page, nil)
	if err != nil || len(releasePage.Items) != 1 || releasePage.Items[0].ID != "draft_release" || releasePage.Next != nil {
		t.Fatalf("release-granted page=%#v error=%v", releasePage, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"package:read"}}
	if _, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{ProductID: "prod_b"}, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign product filter error=%v", err)
	}
	if _, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{ProductID: "prod_other"}, page, nil); !errors.Is(err, packagequery.ErrNotFound) {
		t.Fatalf("cross-tenant product filter error=%v", err)
	}
	if _, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{ProductID: "prod_a", ReleaseID: "rel_prod_b"}, page, nil); !errors.Is(err, packagequery.ErrValidation) {
		t.Fatalf("mismatched parent filters error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"package:read"}}
	page.PageSize = 10
	all, err := service.ListPage(ctx, actor, packagequery.AnswerLibraryFilter{}, page, nil)
	if err != nil || len(all.Items) != 4 || all.Next != nil {
		t.Fatalf("tenant page=%#v error=%v", all, err)
	}
	request := packagequery.AnswerLibraryPageRequest{TenantID: actor.TenantID, TenantWide: true, Page: page, After: &appquery.SortKey{ID: "draft_a", Value: "other"}}
	if _, err := store.PageAnswerLibrary(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("bad cursor error=%v", err)
	}
}
