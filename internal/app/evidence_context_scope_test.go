package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func TestLedgerEvidenceReaderValidatesCompleteBuildAndDeploymentScope(t *testing.T) {
	ledger := newEvidenceScopeLedger(t)
	reader := ledgerEvidenceReader{ledger: ledger}
	valid := evidenceapp.EvidenceScope{
		ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_a", BuildID: "build_a", DeploymentID: "dep_a",
	}
	if err := reader.ValidateScope(context.Background(), "ten_a", valid); err != nil {
		t.Fatalf("valid scope: %v", err)
	}
	if err := reader.ValidateScope(context.Background(), "ten_a", evidenceapp.EvidenceScope{
		ProductID: "prod_a", ReleaseID: "rel_a", DeploymentID: "dep_pending", AllowPendingDeployment: true,
	}); err != nil {
		t.Fatalf("pending deployment scope: %v", err)
	}
	if err := reader.ValidateScope(context.Background(), "ten_a", evidenceapp.EvidenceScope{
		ProductID: "prod_a", ReleaseID: "rel_a", DeploymentID: "dep_pending",
	}); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatalf("ordinary missing deployment error = %v, want not found", err)
	}
	for name, scope := range map[string]evidenceapp.EvidenceScope{
		"project belongs to another product": {ProductID: "prod_b", ProjectID: "proj_a"},
		"release conflicts with project":     {ProjectID: "proj_a", ReleaseID: "rel_b"},
		"build conflicts with release":       {ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_b", BuildID: "build_a"},
		"deployment conflicts with release":  {ProductID: "prod_a", ReleaseID: "rel_b", DeploymentID: "dep_a"},
		"foreign tenant build":               {BuildID: "build_foreign"},
		"missing deployment":                 {DeploymentID: "dep_missing"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := reader.ValidateScope(context.Background(), "ten_a", scope); !errors.Is(err, evidenceapp.ErrNotFound) {
				t.Fatalf("ValidateScope error = %v, want not found", err)
			}
		})
	}
}

func TestLedgerEvidenceTransactionRevalidatesScopeInDurableRepository(t *testing.T) {
	ledger := newEvidenceScopeLedger(t)
	spy := &evidenceScopeRepositorySpy{}
	repositories := Repositories{Evidence: spy}
	tx := newLedgerEvidenceTransaction(ledger)
	tx.repositories = &repositories
	scope := evidenceapp.EvidenceScope{
		ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_a", BuildID: "build_a", DeploymentID: "dep_a",
	}
	if err := tx.ValidateScope(context.Background(), "ten_a", scope); err != nil {
		t.Fatalf("ValidateScope: %v", err)
	}
	if spy.calls != 1 || spy.tenantID != "ten_a" || spy.scope != scope {
		t.Fatalf("durable scope validation = %#v", spy)
	}
	pending := evidenceapp.EvidenceScope{
		ProductID: "prod_a", ReleaseID: "rel_a", DeploymentID: "dep_pending", AllowPendingDeployment: true,
	}
	if err := tx.ValidateScope(context.Background(), "ten_a", pending); err != nil {
		t.Fatalf("pending ValidateScope: %v", err)
	}
	if spy.calls != 2 || spy.scope.DeploymentID != "" {
		t.Fatalf("pending durable scope validation = %#v", spy)
	}
}

func TestLedgerEvidenceTransactionRevalidatesArtifactReferenceInDurableRepository(t *testing.T) {
	ledger := newEvidenceScopeLedger(t)
	lookup := &artifactLookupRepository{artifact: ledger.artifacts["art_a"]}
	repositories := Repositories{ReleaseCatalog: lookup}
	tx := newLedgerEvidenceTransaction(ledger)
	tx.repositories = &repositories

	if err := tx.ValidateArtifactReference(context.Background(), "ten_a", "art_a", ledger.artifacts["art_a"].Digest); err != nil {
		t.Fatalf("ValidateArtifactReference: %v", err)
	}
	if lookup.calls != 1 || lookup.tenantID != "ten_a" || lookup.artifactID != "art_a" {
		t.Fatalf("durable artifact lookup = %#v", lookup)
	}
	lookup.artifact.Digest = "sha256:" + strings.Repeat("f", 64)
	if err := tx.ValidateArtifactReference(context.Background(), "ten_a", "art_a", ledger.artifacts["art_a"].Digest); !errors.Is(err, evidenceapp.ErrConflict) {
		t.Fatalf("drifted artifact error = %v, want conflict", err)
	}
}

func TestLedgerEvidenceReaderRejectsMismatchedArtifactReferenceDigest(t *testing.T) {
	ledger := newEvidenceScopeLedger(t)
	reader := ledgerEvidenceReader{ledger: ledger}

	if err := reader.ValidateArtifactReference(context.Background(), "ten_a", "art_a", ledger.artifacts["art_a"].Digest); err != nil {
		t.Fatalf("matching artifact reference: %v", err)
	}
	if err := reader.ValidateArtifactReference(context.Background(), "ten_a", "art_a", "sha256:"+strings.Repeat("f", 64)); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatalf("mismatched digest error = %v, want not found", err)
	}
}

func TestLedgerEvidenceTransactionReadsDurableEvidenceProjections(t *testing.T) {
	ledger := newEvidenceScopeLedger(t)
	ledger.evidence["ev_durable"] = domain.EvidenceItem{ID: "ev_durable", TenantID: "ten_a", Title: "cached evidence"}
	ledger.sboms["sbom_durable"] = domain.SBOM{ID: "sbom_durable", TenantID: "ten_a", Format: "cached"}
	ledger.contracts["oas_durable"] = domain.OpenAPIContract{ID: "oas_durable", TenantID: "ten_a", Version: "cached"}

	spy := &evidenceScopeRepositorySpy{
		evidence: domain.EvidenceItem{ID: "ev_durable", TenantID: "ten_a", Title: "durable evidence"},
		sbom:     domain.SBOM{ID: "sbom_durable", TenantID: "ten_a", Format: "cyclonedx"},
		contract: domain.OpenAPIContract{ID: "oas_durable", TenantID: "ten_a", Version: "v2"},
	}
	repositories := Repositories{Evidence: spy}
	tx := newLedgerEvidenceTransaction(ledger)
	tx.repositories = &repositories

	evidence, err := tx.GetEvidence(context.Background(), "ten_a", "ev_durable")
	if err != nil {
		t.Fatalf("GetEvidence: %v", err)
	}
	sbom, err := tx.GetSBOM(context.Background(), "ten_a", "sbom_durable")
	if err != nil {
		t.Fatalf("GetSBOM: %v", err)
	}
	contract, err := tx.GetOpenAPIContract(context.Background(), "ten_a", "oas_durable")
	if err != nil {
		t.Fatalf("GetOpenAPIContract: %v", err)
	}
	if evidence.Title != spy.evidence.Title || sbom.Format != spy.sbom.Format || contract.Version != spy.contract.Version {
		t.Fatalf("transaction reads were not durable: evidence=%#v sbom=%#v contract=%#v", evidence, sbom, contract)
	}
	if spy.evidenceReads != 1 || spy.sbomReads != 1 || spy.contractReads != 1 {
		t.Fatalf("durable repository reads = evidence:%d sbom:%d contract:%d", spy.evidenceReads, spy.sbomReads, spy.contractReads)
	}
}

type artifactLookupRepository struct {
	ReleaseCatalogRepository
	artifact             domain.Artifact
	calls                int
	tenantID, artifactID string
}

func (r *artifactLookupRepository) GetArtifact(_ context.Context, tenantID, artifactID string) (domain.Artifact, error) {
	r.calls++
	r.tenantID, r.artifactID = tenantID, artifactID
	return r.artifact, nil
}

type evidenceScopeRepositorySpy struct {
	EvidenceRepository
	calls                                   int
	tenantID                                string
	scope                                   evidenceapp.EvidenceScope
	evidence                                domain.EvidenceItem
	sbom                                    domain.SBOM
	contract                                domain.OpenAPIContract
	evidenceReads, sbomReads, contractReads int
}

func (s *evidenceScopeRepositorySpy) ValidateEvidenceScope(_ context.Context, tenantID, productID, projectID, releaseID, buildID, deploymentID string) error {
	s.calls++
	s.tenantID = tenantID
	s.scope = evidenceapp.EvidenceScope{
		ProductID: productID, ProjectID: projectID, ReleaseID: releaseID, BuildID: buildID, DeploymentID: deploymentID,
	}
	return nil
}

func (s *evidenceScopeRepositorySpy) GetEvidence(_ context.Context, tenantID, id string) (domain.EvidenceItem, error) {
	s.evidenceReads++
	if s.evidence.ID != id || s.evidence.TenantID != tenantID {
		return domain.EvidenceItem{}, ErrNotFound
	}
	return s.evidence, nil
}

func (s *evidenceScopeRepositorySpy) GetSBOM(_ context.Context, tenantID, id string) (domain.SBOM, error) {
	s.sbomReads++
	if s.sbom.ID != id || s.sbom.TenantID != tenantID {
		return domain.SBOM{}, ErrNotFound
	}
	return s.sbom, nil
}

func (s *evidenceScopeRepositorySpy) GetOpenAPIContract(_ context.Context, tenantID, id string) (domain.OpenAPIContract, error) {
	s.contractReads++
	if s.contract.ID != id || s.contract.TenantID != tenantID {
		return domain.OpenAPIContract{}, ErrNotFound
	}
	return s.contract, nil
}

func newEvidenceScopeLedger(t *testing.T) *Ledger {
	t.Helper()
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: func() time.Time { return now }})
	ledger.tenants["ten_a"] = domain.Tenant{ID: "ten_a"}
	ledger.products["prod_a"] = domain.Product{ID: "prod_a", TenantID: "ten_a"}
	ledger.products["prod_b"] = domain.Product{ID: "prod_b", TenantID: "ten_a"}
	ledger.projects["proj_a"] = domain.Project{ID: "proj_a", TenantID: "ten_a", ProductID: "prod_a"}
	ledger.releases["rel_a"] = domain.Release{ID: "rel_a", TenantID: "ten_a", ProductID: "prod_a"}
	ledger.releases["rel_b"] = domain.Release{ID: "rel_b", TenantID: "ten_a", ProductID: "prod_b"}
	ledger.buildRuns["build_a"] = domain.BuildRun{ID: "build_a", TenantID: "ten_a", ProjectID: "proj_a", ReleaseID: "rel_a"}
	ledger.buildRuns["build_foreign"] = domain.BuildRun{ID: "build_foreign", TenantID: "ten_b", ProjectID: "proj_a", ReleaseID: "rel_a"}
	ledger.environments["env_a"] = domain.DeploymentEnvironment{ID: "env_a", TenantID: "ten_a", ProductID: "prod_a"}
	ledger.deployments["dep_a"] = domain.DeploymentEvent{ID: "dep_a", TenantID: "ten_a", EnvironmentID: "env_a", ReleaseID: "rel_a"}
	ledger.artifacts["art_a"] = domain.Artifact{ID: "art_a", TenantID: "ten_a", Name: "artifact", MediaType: "application/octet-stream", Size: 42, Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: now}
	return ledger
}
