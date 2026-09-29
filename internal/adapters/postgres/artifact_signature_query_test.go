package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestPostgresArtifactSignaturePointScopesCurrentAssociations(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_signature", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ product, tenant string }{{"prod_a", "ten_signature"}, {"prod_b", "ten_signature"}, {"prod_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, parent.product, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, artifact := range []struct{ id, tenant, digest string }{{"art_a", "ten_signature", "sha256:subject"}, {"art_other", "ten_other", "sha256:other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ($1, $2, $1, 'application/octet-stream', 1, $3, $4)`, artifact.id, artifact.tenant, artifact.digest, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, signature := range []struct{ id, tenant, artifact, digest string }{
		{"sig_a", "ten_signature", "art_a", "sha256:subject"},
		{"sig_bad_digest", "ten_signature", "art_a", "sha256:wrong"},
		{"sig_other", "ten_other", "art_other", "sha256:other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO artifact_signatures (id, tenant_id, artifact_id, subject_digest, algorithm, signature, payload_ref, verification_status, schema_version, created_at) VALUES ($1, $2, $3, $4, 'ed25519', 'signed', 'private/object/ref', 'recorded', 'artifact-signature.v1.0.0', $5)`, signature.id, signature.tenant, signature.artifact, signature.digest, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, build := range []struct{ id, project, release, digest string }{
		{"bld_valid", "proj_prod_a", "rel_prod_a", "sha256:subject"},
		{"bld_cross_product", "proj_prod_b", "rel_prod_a", "sha256:subject"},
		{"bld_wrong_digest", "proj_prod_b", "rel_prod_b", "sha256:wrong"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version, created_at) VALUES ($1, 'ten_signature', $2, $3, 'test', '0123456789abcdef', 'passed', $4, jsonb_build_array(jsonb_build_object('artifact_id', 'art_a', 'digest', $5::text)), 'v1', $4)`, build.id, build.project, build.release, now, build.digest); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ('ev_cross_product', 'ten_signature', 'prod_b', 'rel_prod_a', 'document', 'Artifact', 'test', $1, 1, 'evidence-item.v1.0.0', 'sha256:payload', 'sha256:canonical', 'canonical-json.v1', '[{"type":"artifact","id":"art_a"}]'::jsonb, 'L2', 'pending', $1)`, now); err != nil {
		t.Fatal(err)
	}
	service, err := verificationquery.NewArtifactSignatures(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_signature", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"evidence:read"}}}}
	if signature, err := service.GetArtifactSignature(ctx, actor, "sig_a"); err != nil || signature.ID != "sig_a" || signature.PayloadRef != "private/object/ref" {
		t.Fatalf("product-granted signature=%#v error=%v", signature, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "project", ResourceID: "proj_prod_a", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(ctx, actor, "sig_a"); err != nil {
		t.Fatalf("project-granted signature error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_prod_a", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(ctx, actor, "sig_a"); err != nil {
		t.Fatalf("release-granted signature error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(ctx, actor, "sig_a"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong-product signature error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(ctx, actor, "sig_a"); err != nil {
		t.Fatalf("tenant-granted signature error=%v", err)
	}
	for _, id := range []string{"sig_bad_digest", "sig_other", "sig_missing"} {
		if _, err := service.GetArtifactSignature(ctx, actor, id); !errors.Is(err, verificationquery.ErrSignatureNotFound) {
			t.Fatalf("unsafe signature %s error=%v", id, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ('ev_art_b', 'ten_signature', 'prod_b', 'document', 'Artifact', 'test', $1, 1, 'evidence-item.v1.0.0', 'sha256:payload', 'sha256:canonical', 'canonical-json.v1', '[{"type":"artifact","id":"art_a"}]'::jsonb, 'L2', 'pending', $1)`, now); err != nil {
		t.Fatal(err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(ctx, actor, "sig_a"); err != nil {
		t.Fatalf("evidence-linked product signature error=%v", err)
	}
}
