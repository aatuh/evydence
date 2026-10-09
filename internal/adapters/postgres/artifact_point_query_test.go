package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestPostgresArtifactPointUsesCurrentTenantSafeAssociations(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	digest := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	for _, tenant := range []string{"ten_artifact", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ id, tenant string }{{"a", "ten_artifact"}, {"b", "ten_artifact"}, {"other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+parent.id, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+parent.id, parent.tenant, "prod_"+parent.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.id, parent.tenant, "prod_"+parent.id, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, artifact := range []struct{ id, tenant string }{{"art_a", "ten_artifact"}, {"art_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ($1, $2, $1, 'application/octet-stream', 1, $3, $4)`, artifact.id, artifact.tenant, digest, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, project_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ('ev_bad_parent', 'ten_artifact', 'prod_b', 'proj_a', 'rel_a', 'document', 'Artifact', 'test', $1, 1, 'evidence-item.v1.0.0', $2, $2, 'canonical-json.v1', '[{"type":"artifact","id":"art_a"}]'::jsonb, 'L2', 'pending', $1)`, now, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version, created_at) VALUES ('bld_bad_parent', 'ten_artifact', 'proj_b', 'rel_a', 'test', '0123456789abcdef', 'passed', $1, jsonb_build_array(jsonb_build_object('artifact_id', 'art_a', 'digest', $2::text)), 'v1', $1)`, now, digest); err != nil {
		t.Fatal(err)
	}
	service, err := releasequery.NewArtifactPoints(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_artifact", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"evidence:read"}}}}
	if _, err := service.GetArtifact(ctx, actor, "art_a"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("inconsistent product association error=%v", err)
	}
	if _, err := service.GetArtifact(ctx, actor, "art_other"); !errors.Is(err, releasequery.ErrNotFound) {
		t.Fatalf("foreign artifact error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, project_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ('ev_artifact', 'ten_artifact', 'prod_a', 'proj_a', 'rel_a', 'document', 'Artifact', 'test', $1, 1, 'evidence-item.v1.0.0', $2, $2, 'canonical-json.v1', '[{"type":"artifact","id":"art_a"}]'::jsonb, 'L2', 'pending', $1)`, now, digest); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct{ kind, id string }{{"product", "prod_a"}, {"project", "proj_a"}, {"release", "rel_a"}} {
		actor.ResourceGrants[0].ResourceType, actor.ResourceGrants[0].ResourceID = grant.kind, grant.id
		if artifact, err := service.GetArtifact(ctx, actor, "art_a"); err != nil || artifact.ID != "art_a" {
			t.Fatalf("%s grant artifact=%#v error=%v", grant.kind, artifact, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM evidence_items WHERE id = 'ev_artifact'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version, created_at) VALUES ('bld_artifact', 'ten_artifact', 'proj_a', 'rel_a', 'test', '0123456789abcdef', 'passed', $1, jsonb_build_array(jsonb_build_object('artifact_id', 'art_a', 'digest', $2::text)), 'v1', $1)`, now, digest); err != nil {
		t.Fatal(err)
	}
	if artifact, err := service.GetArtifact(ctx, actor, "art_a"); err != nil || artifact.ID != "art_a" {
		t.Fatalf("build-linked artifact=%#v error=%v", artifact, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE build_runs SET outputs = '[{"artifact_id":"art_a","digest":"sha256:wrong"}]'::jsonb WHERE id = 'bld_artifact'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetArtifact(ctx, actor, "art_a"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("mismatched build digest error=%v", err)
	}
}
