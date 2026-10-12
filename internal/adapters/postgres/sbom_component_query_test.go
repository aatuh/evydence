package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSBOMComponentsPageBeyondLegacyCapAndScopesGrants(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	hash := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	for _, tenant := range []string{"ten_sbom", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ suffix, tenant string }{{"a", "ten_sbom"}, {"b", "ten_sbom"}, {"other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+parent.suffix, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, $2, $3, $4, 'sbom', 'SBOM', 'test', $5, 1, 'evidence-item.v1.0.0', $6, $6, 'canonical-json.v1', 'L2', 'pending', $5)`, "ev_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, "rel_"+parent.suffix, now, hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ('art_a', 'ten_sbom', 'Artifact', 'application/octet-stream', 1, $1, $2)`, hash, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET subject_refs = '[{"type":"artifact","id":"art_a"}]'::jsonb WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	components := make([]map[string]string, 501)
	for index := range components {
		components[index] = map[string]string{"identity": fmt.Sprintf("component-%03d", index), "name": fmt.Sprintf("lib-%03d", index), "version": "1.0", "purl": fmt.Sprintf("pkg:generic/lib-%03d@1.0", index)}
	}
	encoded, err := json.Marshal(components)
	if err != nil {
		t.Fatal(err)
	}
	for _, sbom := range []struct {
		id, tenant, evidence, release, artifact string
		components                              any
		count                                   int
	}{
		{"sbom_a", "ten_sbom", "ev_a", "rel_a", "art_a", encoded, len(components)},
		{"sbom_bad", "ten_sbom", "ev_b", "rel_a", "", `[{"name":"bad"}]`, 1},
		{"sbom_other", "ten_other", "ev_other", "rel_other", "", `[{"name":"other"}]`, 1},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components, created_at) VALUES ($1, $2, $3, $4, NULLIF($5, ''), 'cyclonedx', '1.6', $6, $7, $8)`, sbom.id, sbom.tenant, sbom.evidence, sbom.release, sbom.artifact, sbom.count, sbom.components, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := evidencequery.NewSBOMComponents(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_sbom", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"evidence:read"}}}}
	page := appquery.PageRequest{PageSize: 500, Sort: appquery.SortID, Direction: appquery.Ascending}
	first, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, page, nil)
	if err != nil || len(first.Items) != 500 || first.Next == nil {
		t.Fatalf("first page count=%d next=%#v error=%v", len(first.Items), first.Next, err)
	}
	second, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, page, first.Next)
	if err != nil || len(second.Items) != 1 || second.Next != nil || second.Items[0].Component.Name != "lib-099" {
		t.Fatalf("second page=%#v error=%v", second, err)
	}
	seen := make(map[string]bool, 501)
	for _, item := range append(first.Items, second.Items...) {
		if seen[item.ID] {
			t.Fatalf("duplicate component %s across pages", item.ID)
		}
		seen[item.ID] = true
	}
	if len(seen) != 501 {
		t.Fatalf("pagination covered %d components, want 501", len(seen))
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"evidence:read"}}
	beforeLink, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, page, nil)
	if err != nil || len(beforeLink.Items) != 500 {
		t.Fatalf("source-linked artifact product page count=%d error=%v", len(beforeLink.Items), err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, project_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ('ev_art', 'ten_sbom', 'prod_a', 'proj_a', 'rel_a', 'document', 'Artifact', 'test', $1, 1, 'evidence-item.v1.0.0', $2, $2, 'canonical-json.v1', '[{"type":"artifact","id":"art_a"}]'::jsonb, 'L2', 'pending', $1)`, now, hash); err != nil {
		t.Fatal(err)
	}
	linked, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a", Query: "LIB-500", PURL: "pkg:generic/lib-500@1.0"}, page, nil)
	if err != nil || len(linked.Items) != 1 || linked.Items[0].Component.Identity != "component-500" {
		t.Fatalf("linked search=%#v error=%v", linked, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "project", ResourceID: "proj_a", Scopes: []string{"evidence:read"}}
	if result, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); err != nil || len(result.Items) != 1 {
		t.Fatalf("project grant result=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"evidence:read"}}
	if result, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{}, page, nil); err != nil || len(result.Items) != 0 {
		t.Fatalf("wrong product result=%#v error=%v", result, err)
	}
	if _, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, page, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("same-tenant hidden SBOM error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_sbom", Scopes: []string{"evidence:read"}}
	if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ('art_b', 'ten_sbom', 'Artifact B', 'application/octet-stream', 1, $1, $2)`, "sha256:"+strings.Repeat("b", 64), now); err != nil {
		t.Fatal(err)
	}
	for _, evidence := range []struct{ id, release, kind string }{{"ev_wrong_type", "rel_a", "document"}, {"ev_no_release", "", "sbom"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, 'ten_sbom', 'prod_a', NULLIF($2, ''), $3, 'Source', 'test', $4, 1, 'evidence-item.v1.0.0', $5, $5, 'canonical-json.v1', 'L2', 'pending', $4)`, evidence.id, evidence.release, evidence.kind, now, hash); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ id, column string }{{"ev_missing_build", "build_id"}, {"ev_missing_deployment", "deployment_id"}} {
		statement := fmt.Sprintf(`INSERT INTO evidence_items (id, tenant_id, product_id, release_id, %s, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, 'ten_sbom', 'prod_a', 'rel_a', $2, 'sbom', 'Source', 'test', $3, 1, 'evidence-item.v1.0.0', $4, $4, 'canonical-json.v1', 'L2', 'pending', $3)`, parent.column)
		if _, err := store.pool.Exec(ctx, statement, parent.id, "missing_parent", now, hash); err != nil {
			t.Fatal(err)
		}
	}
	for _, sbom := range []struct{ id, evidence, artifact string }{
		{"sbom_wrong_type", "ev_wrong_type", ""},
		{"sbom_missing_source_release", "ev_no_release", ""},
		{"sbom_missing_source_build", "ev_missing_build", ""},
		{"sbom_missing_source_deployment", "ev_missing_deployment", ""},
		{"sbom_wrong_artifact", "ev_a", "art_b"},
		{"sbom_missing_artifact_link", "ev_a", ""},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components, created_at) VALUES ($1, 'ten_sbom', $2, 'rel_a', NULLIF($3, ''), 'cyclonedx', '1.6', 1, '[{"name":"bad"}]'::jsonb, $4)`, sbom.id, sbom.evidence, sbom.artifact, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sbom_wrong_type", "sbom_missing_source_release", "sbom_missing_source_build", "sbom_missing_source_deployment", "sbom_wrong_artifact", "sbom_missing_artifact_link"} {
		if _, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: id}, page, nil); !errors.Is(err, evidencequery.ErrNotFound) {
			t.Fatalf("unsafe SBOM source %s error=%v", id, err)
		}
	}
	largeComponent, err := json.Marshal([]map[string]string{{"name": strings.Repeat("n", 700000), "version": strings.Repeat("v", 700000)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id, tenant_id, evidence_id, release_id, format, spec_version, component_count, components, created_at) VALUES ('sbom_large', 'ten_sbom', 'ev_b', 'rel_b', 'cyclonedx', '1.6', 1, $1, $2)`, largeComponent, now); err != nil {
		t.Fatal(err)
	}
	if result, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_large"}, page, nil); err != nil || len(result.Items) != 1 || len(result.Items[0].Component.Name) != 700000 {
		t.Fatalf("large valid component length=%d error=%v", len(result.Items), err)
	}
	if _, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_other"}, page, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("foreign SBOM error=%v", err)
	}
	if _, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_bad"}, page, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("inconsistent SBOM parent error=%v", err)
	}
	if result, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a", ReleaseID: "rel_b"}, page, nil); err != nil || len(result.Items) != 0 {
		t.Fatalf("mismatched release filter result=%#v error=%v", result, err)
	}
	if result, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Descending}, nil); err != nil || len(result.Items) != 1 || result.Items[0].ID != "sbom_a:99" || result.Next == nil {
		t.Fatalf("descending page=%#v error=%v", result, err)
	}
	if result, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{}, page, nil); err != nil || len(result.Items) != 500 {
		t.Fatalf("tenant page=%#v error=%v", result, err)
	}
	if _, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_missing"}, page, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("missing SBOM error=%v", err)
	}
	noScope := actor
	noScope.Scopes = nil
	if _, err := service.ListPage(ctx, noScope, evidencequery.SBOMComponentFilter{}, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET subject_refs = '[{"type":"artifact","id":"art_a"},{"type":"artifact","id":"art_b"}]'::jsonb WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom_a"}, page, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("ambiguous source artifact references error=%v", err)
	}
}
