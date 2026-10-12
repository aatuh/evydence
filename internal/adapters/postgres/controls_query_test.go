package postgres

import (
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestPostgresControlsQueriesScopeTenantAndCurrentParent(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, framework := range []struct{ id, tenant string }{{"fw_a", "ten_controls"}, {"fw_b", "ten_controls"}, {"fw_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_frameworks (id, tenant_id, name, slug, version, status, schema_version, created_at) VALUES ($1, $2, $1, $1, '1', 'active', 'control-framework.v1.0.0', $3)`, framework.id, framework.tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, control := range []struct{ id, tenant, framework string }{
		{"ctrl_a", "ten_controls", "fw_a"}, {"ctrl_cross_parent", "ten_controls", "fw_other"}, {"ctrl_other", "ten_other", "fw_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO security_controls (id, tenant_id, framework_id, code, title, objective, evidence_requirements, applicability, limitations, schema_version, created_at) VALUES ($1, $2, $3, $1, $1, 'Check build evidence', '[{"type":"build","freshness_days":7,"required":true}]'::jsonb, '["release"]'::jsonb, '[]'::jsonb, 'security-control.v1.0.0', $4)`, control.id, control.tenant, control.framework, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := riskquery.NewControls(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_controls", KeyID: "key_1", Scopes: []string{"controls:read"}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	first, err := service.ListFrameworksPage(ctx, actor, page, nil)
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != "fw_a" || first.Next == nil {
		t.Fatalf("first framework page=%#v error=%v", first, err)
	}
	second, err := service.ListFrameworksPage(ctx, actor, page, first.Next)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "fw_b" || second.Next != nil {
		t.Fatalf("second framework page=%#v error=%v", second, err)
	}
	page.Sort = appquery.SortID
	page.Direction = appquery.Descending
	last, err := service.ListFrameworksPage(ctx, actor, page, nil)
	if err != nil || len(last.Items) != 1 || last.Items[0].ID != "fw_b" || last.Next == nil {
		t.Fatalf("descending framework page=%#v error=%v", last, err)
	}
	control, err := service.GetSecurityControl(ctx, actor, "ctrl_a")
	if err != nil || control.ID != "ctrl_a" || len(control.EvidenceRequirements) != 1 || control.EvidenceRequirements[0].FreshnessDays != 7 || len(control.Applicability) != 1 {
		t.Fatalf("control point=%#v error=%v", control, err)
	}
	for _, id := range []string{"ctrl_cross_parent", "ctrl_other", "ctrl_missing"} {
		if _, err := service.GetSecurityControl(ctx, actor, id); !errors.Is(err, riskquery.ErrNotFound) {
			t.Fatalf("unsafe control %s error=%v", id, err)
		}
	}
	request := riskquery.FrameworkPageRequest{TenantID: "ten_controls", Page: page, After: &appquery.SortKey{ID: "fw_a", Value: "not-the-id"}}
	if _, err := store.PageFrameworks(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed cursor error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE security_controls SET evidence_requirements = '{}'::jsonb WHERE id = 'ctrl_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetSecurityControl(ctx, actor, "ctrl_a"); !errors.Is(err, riskquery.ErrInvalidProjection) {
		t.Fatalf("malformed stored requirements error=%v", err)
	}
}
