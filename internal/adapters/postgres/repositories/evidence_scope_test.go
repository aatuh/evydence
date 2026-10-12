package repositories_test

import (
	"errors"
	"testing"
	"time"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestEvidenceRepositoryValidatesBuildAndDeploymentScope(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	now := time.Now().UTC().Round(0)
	for _, tenantID := range []string{"ten_scope_a", "ten_scope_b"} {
		suffix := tenantID[len(tenantID)-1:]
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)`, tenantID, tenantID, now); err != nil {
			t.Fatalf("seed tenant %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $3, $4, $5)`, "prod_"+suffix, tenantID, "product "+suffix, "product-"+suffix, now); err != nil {
			t.Fatalf("seed product %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $4, $5)`, "proj_"+suffix, tenantID, "prod_"+suffix, "project "+suffix, now); err != nil {
			t.Fatalf("seed project %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, $4, 'draft', $5)`, "rel_"+suffix, tenantID, "prod_"+suffix, "1.0."+suffix, now); err != nil {
			t.Fatalf("seed release %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version, created_at) VALUES ($1, $2, $3, $4, 'generic_ci', $5, 'passed', $6, '[]'::jsonb, 'build-run.v1.0.0', $6)`, "build_"+suffix, tenantID, "proj_"+suffix, "rel_"+suffix, "0123456789abcdef0123456789abcdef0123456"+suffix, now); err != nil {
			t.Fatalf("seed build %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO deployment_environments (id, tenant_id, product_id, name, kind, schema_version, created_at) VALUES ($1, $2, $3, $4, 'production', 'deployment-environment.v1.0.0', $5)`, "env_"+suffix, tenantID, "prod_"+suffix, "environment "+suffix, now); err != nil {
			t.Fatalf("seed environment %s: %v", tenantID, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO deployment_events (id, tenant_id, environment_id, release_id, status, started_at, schema_version, created_at) VALUES ($1, $2, $3, $4, 'succeeded', $5, 'deployment-event.v1.0.0', $5)`, "dep_"+suffix, tenantID, "env_"+suffix, "rel_"+suffix, now); err != nil {
			t.Fatalf("seed deployment %s: %v", tenantID, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ('prod_a_alt', 'ten_scope_a', 'alternate product', 'alternate-product', $1)`, now); err != nil {
		t.Fatalf("seed alternate product: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ('proj_a_alt', 'ten_scope_a', 'prod_a_alt', 'alternate project', $1)`, now); err != nil {
		t.Fatalf("seed alternate project: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ('rel_a_alt', 'ten_scope_a', 'prod_a_alt', '2.0.0', 'draft', $1)`, now); err != nil {
		t.Fatalf("seed alternate release: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	repository := postgresrepositories.New(tx).Evidence

	if err := repository.ValidateEvidenceScope(ctx, "ten_scope_a", "prod_a", "proj_a", "rel_a", "build_a", "dep_a"); err != nil {
		t.Fatalf("valid scope: %v", err)
	}
	for name, scope := range map[string][6]string{
		"foreign build":      {"ten_scope_a", "prod_a", "proj_a", "rel_a", "build_b", ""},
		"missing build":      {"ten_scope_a", "prod_a", "proj_a", "rel_a", "build_missing", ""},
		"foreign deployment": {"ten_scope_a", "prod_a", "", "rel_a", "", "dep_b"},
		"missing deployment": {"ten_scope_a", "prod_a", "", "rel_a", "", "dep_missing"},
		"mixed coordinates":  {"ten_scope_a", "prod_b", "proj_a", "rel_a", "build_a", "dep_a"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := repository.ValidateEvidenceScope(ctx, scope[0], scope[1], scope[2], scope[3], scope[4], scope[5]); !errors.Is(err, app.ErrNotFound) {
				t.Fatalf("ValidateEvidenceScope error = %v, want not found", err)
			}
		})
	}

	base := domain.EvidenceItem{
		ID: "evi_scope", TenantID: "ten_scope_a", ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_a",
		Type: "note", Title: "scope validation", SourceSystem: "test", ObservedAt: now,
		SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical",
		Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now,
	}
	for name, coordinate := range map[string]struct {
		buildID      string
		deploymentID string
	}{
		"foreign build":      {buildID: "build_b"},
		"missing build":      {buildID: "build_missing"},
		"foreign deployment": {deploymentID: "dep_b"},
		"missing deployment": {deploymentID: "dep_missing"},
	} {
		t.Run("insert rejects "+name, func(t *testing.T) {
			item := base
			item.ID = "evi_" + coordinate.buildID + coordinate.deploymentID
			item.BuildID = coordinate.buildID
			item.DeploymentID = coordinate.deploymentID
			if err := repository.InsertEvidence(ctx, item); !errors.Is(err, app.ErrNotFound) {
				t.Fatalf("InsertEvidence error = %v, want not found", err)
			}
		})
	}

	if err := repository.InsertEvidence(ctx, base); err != nil {
		t.Fatalf("insert valid evidence: %v", err)
	}
	mixed := base
	mixed.ReleaseID = "rel_a_alt"
	if err := repository.CompareAndSwapEvidenceLinks(ctx, base, mixed); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("CompareAndSwapEvidenceLinks error = %v, want not found", err)
	}

	pending := base
	pending.ID = "evi_dep_pending"
	pending.ProductID = "prod_a_alt"
	pending.ProjectID = ""
	pending.ReleaseID = "rel_a_alt"
	pending.DeploymentID = "dep_pending"
	pending.Type = "deployment"
	pending.Subtype = "event"
	if err := repository.InsertEvidence(ctx, pending); err != nil {
		t.Fatalf("insert pending deployment evidence: %v", err)
	}
	if err := postgresrepositories.New(tx).Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{
		ID: "dep_pending", TenantID: "ten_scope_a", EnvironmentID: "env_a", ReleaseID: "rel_a",
		Status: "succeeded", StartedAt: now, EvidenceID: pending.ID,
		SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: now,
	}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("InsertDeploymentEvent error = %v, want not found", err)
	}
}
