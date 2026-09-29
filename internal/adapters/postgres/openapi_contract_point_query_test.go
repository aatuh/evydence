package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresOpenAPIContractPointScopesCurrentParents(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	hash := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	for _, tenant := range []string{"ten_contract", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ suffix, tenant string }{{"a", "ten_contract"}, {"b", "ten_contract"}, {"other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+parent.suffix, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, $2, $3, $4, 'openapi_contract', 'Contract', 'test', $5, 1, 'evidence-item.v1.0.0', $6, $6, 'canonical-json.v1', 'L2', 'pending', $5)`, "ev_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, "rel_"+parent.suffix, now, hash); err != nil {
			t.Fatal(err)
		}
	}
	for _, contract := range []struct{ id, tenant, product, release, evidence string }{
		{"con_good", "ten_contract", "prod_a", "rel_a", "ev_a"},
		{"con_cross_product", "ten_contract", "prod_b", "rel_a", "ev_a"},
		{"con_cross_evidence", "ten_contract", "prod_a", "rel_a", "ev_other"},
		{"con_other", "ten_other", "prod_other", "rel_other", "ev_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO openapi_contracts (id, tenant_id, product_id, release_id, version, hash, path_count, operations, evidence_id, created_at) VALUES ($1, $2, $3, $4, '1.0', $5, 1, '[{"path":"/v1/items","method":"GET","operation_id":"listItems","required_request_fields":["id"],"response_statuses":["200"]}]'::jsonb, $6, $7)`, contract.id, contract.tenant, contract.product, contract.release, hash, contract.evidence, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := evidencequery.NewOpenAPIContractPoints(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_contract", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"evidence:read"}}}}
	contract, err := service.GetOpenAPIContract(ctx, actor, "con_good")
	if err != nil || contract.ID != "con_good" || len(contract.Operations) != 1 || contract.Operations[0].OperationID != "listItems" || len(contract.Operations[0].RequiredRequestFields) != 1 {
		t.Fatalf("contract=%#v error=%v", contract, err)
	}
	job := ClaimedJob{TenantID: "ten_contract", Kind: "parse_openapi_contract", SubjectID: "con_good"}
	state, ok, err := store.LoadParserJobState(ctx, job)
	if err != nil || !ok || len(state.Contracts) != 1 || len(state.Contracts[job.SubjectID].Operations) != 1 {
		t.Fatalf("focused parser state=%#v ok=%v error=%v", state.Contracts, ok, err)
	}
	job.TenantID = "ten_other"
	state, ok, err = store.LoadParserJobState(ctx, job)
	if err != nil || !ok || len(state.Contracts) != 0 {
		t.Fatalf("foreign parser state=%#v ok=%v error=%v", state.Contracts, ok, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"evidence:read"}}
	if _, err := service.GetOpenAPIContract(ctx, actor, "con_good"); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_b"
	if _, err := service.GetOpenAPIContract(ctx, actor, "con_good"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong release grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_contract", Scopes: []string{"evidence:read"}}
	for _, id := range []string{"con_cross_product", "con_cross_evidence", "con_other", "con_missing"} {
		if _, err := service.GetOpenAPIContract(ctx, actor, id); !errors.Is(err, evidencequery.ErrNotFound) {
			t.Fatalf("unsafe contract %s error=%v", id, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ('proj_b', 'ten_contract', 'prod_b', 'Project B', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET project_id = 'proj_b' WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetOpenAPIContract(ctx, actor, "con_good"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("cross-product evidence project error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET project_id = NULL WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET type = 'sbom' WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetOpenAPIContract(ctx, actor, "con_good"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("wrong source type error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET type = 'openapi_contract' WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE openapi_contracts SET operations = '{}'::jsonb WHERE id = 'con_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetOpenAPIContract(ctx, actor, "con_good"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatalf("malformed operations error=%v", err)
	}
}
