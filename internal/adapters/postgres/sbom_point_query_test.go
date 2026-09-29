package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSBOMPointScopesCurrentParentsAndGrants(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	hash := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	for _, tenant := range []string{"ten_sbom_point", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ suffix, tenant string }{{"a", "ten_sbom_point"}, {"b", "ten_sbom_point"}, {"other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+parent.suffix, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, $2, $3, $4, 'sbom', 'SBOM', 'test', $5, 1, 'evidence-item.v1.0.0', $6, $6, 'canonical-json.v1', 'L2', 'pending', $5)`, "ev_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, "rel_"+parent.suffix, now, hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ('art_other', 'ten_other', 'Artifact', 'application/octet-stream', 1, $1, $2)`, hash, now); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []struct{ id, digest string }{{"art_a", hash}, {"art_b", "sha256:" + strings.Repeat("b", 64)}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ($1, 'ten_sbom_point', 'Artifact', 'application/octet-stream', 1, $2, $3)`, artifact.id, artifact.digest, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ('ev_art', 'ten_sbom_point', 'prod_a', 'rel_a', 'sbom', 'SBOM', 'test', $1, 1, 'evidence-item.v1.0.0', $2, $2, 'canonical-json.v1', '[{"type":"artifact","id":"art_a"}]'::jsonb, 'L2', 'pending', $1)`, now, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ('ev_no_release', 'ten_sbom_point', 'prod_a', 'sbom', 'SBOM', 'test', $1, 1, 'evidence-item.v1.0.0', $2, $2, 'canonical-json.v1', 'L2', 'pending', $1)`, now, hash); err != nil {
		t.Fatal(err)
	}
	for _, sbom := range []struct {
		id, tenant, evidence, release, artifact, components string
		count                                               int
	}{
		{"sbom_good", "ten_sbom_point", "ev_a", "rel_a", "", `[{"name":"openssl","version":"3.0"}]`, 1},
		{"sbom_cross_source", "ten_sbom_point", "ev_other", "rel_a", "", `[{"name":"bad"}]`, 1},
		{"sbom_wrong_release", "ten_sbom_point", "ev_b", "rel_a", "", `[{"name":"bad"}]`, 1},
		{"sbom_cross_artifact", "ten_sbom_point", "ev_a", "rel_a", "art_other", `[{"name":"bad"}]`, 1},
		{"sbom_art_good", "ten_sbom_point", "ev_art", "rel_a", "art_a", `[{"name":"good"}]`, 1},
		{"sbom_art_wrong", "ten_sbom_point", "ev_art", "rel_a", "art_b", `[{"name":"bad"}]`, 1},
		{"sbom_missing_artifact_link", "ten_sbom_point", "ev_art", "rel_a", "", `[{"name":"bad"}]`, 1},
		{"sbom_missing_source_release", "ten_sbom_point", "ev_no_release", "rel_a", "", `[{"name":"bad"}]`, 1},
		{"sbom_other", "ten_other", "ev_other", "rel_other", "", `[{"name":"other"}]`, 1},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components, created_at) VALUES ($1, $2, $3, $4, NULLIF($5, ''), 'cyclonedx', '1.6', $6, $7, $8)`, sbom.id, sbom.tenant, sbom.evidence, sbom.release, sbom.artifact, sbom.count, sbom.components, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := evidencequery.NewSBOMPoints(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_sbom_point", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"evidence:read"}}}}
	value, err := service.GetSBOM(ctx, actor, "sbom_good")
	if err != nil || value.ID != "sbom_good" || value.ComponentCount != 1 || len(value.Components) != 1 || value.Components[0].Name != "openssl" {
		t.Fatalf("SBOM point=%#v error=%v", value, err)
	}
	if _, err := service.GetSBOM(ctx, actor, "sbom_art_good"); err != nil {
		t.Fatalf("matched artifact reference error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_b"
	if _, err := service.GetSBOM(ctx, actor, "sbom_good"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong product grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"evidence:read"}}
	if _, err := service.GetSBOM(ctx, actor, "sbom_good"); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_sbom_point", Scopes: []string{"evidence:read"}}
	if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id, tenant_id, evidence_id, release_id, format, spec_version, component_count, components, created_at) VALUES ('sbom_empty', 'ten_sbom_point', 'ev_b', 'rel_b', 'cyclonedx', '1.6', 0, 'null'::jsonb, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id, tenant_id, evidence_id, release_id, format, spec_version, component_count, components, created_at) VALUES ('sbom_accepted', 'ten_sbom_point', 'ev_b', 'rel_b', 'cyclonedx', '', 0, 'null'::jsonb, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if empty, err := service.GetSBOM(ctx, actor, "sbom_empty"); err != nil || empty.ID != "sbom_empty" || empty.ComponentCount != 0 || len(empty.Components) != 0 {
		t.Fatalf("valid empty SBOM=%#v error=%v", empty, err)
	}
	if accepted, err := service.GetSBOM(ctx, actor, "sbom_accepted"); err != nil || accepted.ID != "sbom_accepted" || accepted.SpecVersion != "" || accepted.ComponentCount != 0 {
		t.Fatalf("accepted pending SBOM=%#v error=%v", accepted, err)
	}
	for _, id := range []string{"sbom_cross_source", "sbom_wrong_release", "sbom_cross_artifact", "sbom_art_wrong", "sbom_missing_artifact_link", "sbom_missing_source_release", "sbom_other", "sbom_missing"} {
		if _, err := service.GetSBOM(ctx, actor, id); !errors.Is(err, evidencequery.ErrNotFound) {
			t.Fatalf("unsafe SBOM %s error=%v", id, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sboms SET component_count = 2 WHERE id = 'sbom_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetSBOM(ctx, actor, "sbom_good"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatalf("corrupt component count error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sboms SET component_count = 1, components = 'null'::jsonb WHERE id = 'sbom_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetSBOM(ctx, actor, "sbom_good"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatalf("malformed component array error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sboms SET components = '[{"name":"openssl"}]'::jsonb WHERE id = 'sbom_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ('proj_b', 'ten_sbom_point', 'prod_b', 'Project B', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET project_id = 'proj_b' WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetSBOM(ctx, actor, "sbom_good"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("cross-product evidence project error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET subject_refs = '[{"type":"artifact","id":"art_a"},{"type":"artifact","id":"art_b"}]'::jsonb WHERE id = 'ev_art'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetSBOM(ctx, actor, "sbom_art_good"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("ambiguous source artifact references error=%v", err)
	}
}
