package repositories_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

type durableEvidenceRepository interface {
	GetEvidence(context.Context, string, string) (domain.EvidenceItem, error)
	GetSBOM(context.Context, string, string) (domain.SBOM, error)
	GetOpenAPIContract(context.Context, string, string) (domain.OpenAPIContract, error)
	CompareAndSwapEvidenceLinks(context.Context, domain.EvidenceItem, domain.EvidenceItem) error
}

func TestEvidenceRepositoryDurableReadsAndLinkCASRejectStaleWriter(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenant := domain.Tenant{ID: "ten_evidence_cas", Name: "Evidence CAS", CreatedAt: now}
	productA := domain.Product{ID: "prod_evidence_cas_a", TenantID: tenant.ID, Name: "Product A", Slug: "evidence-cas-a", CreatedAt: now}
	productB := domain.Product{ID: "prod_evidence_cas_b", TenantID: tenant.ID, Name: "Product B", Slug: "evidence-cas-b", CreatedAt: now}
	evidence := domain.EvidenceItem{
		ID: "ev_evidence_cas", TenantID: tenant.ID, Type: "sbom", Title: "Evidence CAS", SourceSystem: "test",
		ObservedAt: now, EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical", Canonicalization: domain.CanonicalizationProfileVersion,
		TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now,
	}
	sbom := domain.SBOM{ID: "sbom_evidence_cas", TenantID: tenant.ID, EvidenceID: evidence.ID, Format: "cyclonedx", SpecVersion: "1.6", Components: []domain.SBOMComponent{{Name: "library"}}, ComponentCount: 1, CreatedAt: now}
	contract := domain.OpenAPIContract{ID: "oas_evidence_cas", TenantID: tenant.ID, ProductID: productA.ID, Version: "v1", Hash: "sha256:contract", PathCount: 1, Operations: []domain.OpenAPIOperation{{Path: "/health", Method: "GET"}}, EvidenceID: evidence.ID, CreatedAt: now}

	seed, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin seed transaction: %v", err)
	}
	seedRepositories := postgresrepositories.New(seed)
	for _, step := range []struct {
		name  string
		write func() error
	}{
		{name: "tenant", write: func() error { return seedRepositories.Identity.InsertTenant(ctx, tenant) }},
		{name: "product a", write: func() error { return seedRepositories.ReleaseCatalog.InsertProduct(ctx, productA) }},
		{name: "product b", write: func() error { return seedRepositories.ReleaseCatalog.InsertProduct(ctx, productB) }},
		{name: "evidence", write: func() error { return seedRepositories.Evidence.InsertEvidence(ctx, evidence) }},
		{name: "SBOM", write: func() error { return seedRepositories.Evidence.InsertSBOM(ctx, sbom) }},
		{name: "contract", write: func() error { return seedRepositories.Evidence.InsertOpenAPIContract(ctx, contract) }},
	} {
		if err := step.write(); err != nil {
			_ = seed.Rollback(context.Background())
			t.Fatalf("seed %s: %v", step.name, err)
		}
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatalf("commit seed transaction: %v", err)
	}

	readTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	reader, ok := any(postgresrepositories.New(readTx).Evidence).(durableEvidenceRepository)
	if !ok {
		t.Fatal("evidence repository does not expose durable reads and link CAS")
	}
	expected, err := reader.GetEvidence(ctx, tenant.ID, evidence.ID)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	loadedSBOM, err := reader.GetSBOM(ctx, tenant.ID, sbom.ID)
	if err != nil {
		t.Fatalf("read SBOM: %v", err)
	}
	loadedContract, err := reader.GetOpenAPIContract(ctx, tenant.ID, contract.ID)
	if err != nil {
		t.Fatalf("read OpenAPI contract: %v", err)
	}
	if loadedSBOM.ComponentCount != sbom.ComponentCount || loadedSBOM.Components[0].Name != sbom.Components[0].Name || loadedContract.Operations[0].Path != contract.Operations[0].Path {
		t.Fatalf("durable projections differ: sbom=%#v contract=%#v", loadedSBOM, loadedContract)
	}
	if _, err := reader.GetEvidence(ctx, "ten_other", evidence.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("cross-tenant GetEvidence error = %v, want not found", err)
	}
	if _, err := reader.GetSBOM(ctx, "ten_other", sbom.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("cross-tenant GetSBOM error = %v, want not found", err)
	}
	if _, err := reader.GetOpenAPIContract(ctx, "ten_other", contract.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("cross-tenant GetOpenAPIContract error = %v, want not found", err)
	}
	if err := readTx.Commit(ctx); err != nil {
		t.Fatalf("commit read transaction: %v", err)
	}
	// The compatibility adapters historically normalized an absent slice to an
	// empty slice. Both representations mean there are no related references and
	// must compare equal at the repository boundary.
	expected.RelatedEvidenceRefs = []domain.EvidenceRef{}

	winnerTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin winner transaction: %v", err)
	}
	winnerRepository := postgresrepositories.New(winnerTx).Evidence.(durableEvidenceRepository)
	winner := expected
	winner.Title = "must not replace immutable evidence fields"
	winner.ProductID = productA.ID
	winner.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "product", ID: productA.ID, Relationship: "linked_to"}}
	if err := winnerRepository.CompareAndSwapEvidenceLinks(ctx, expected, winner); err != nil {
		_ = winnerTx.Rollback(context.Background())
		t.Fatalf("commit winning link: %v", err)
	}
	if err := winnerTx.Commit(ctx); err != nil {
		t.Fatalf("commit winner transaction: %v", err)
	}

	staleTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin stale transaction: %v", err)
	}
	defer func() { _ = staleTx.Rollback(context.Background()) }()
	stale := postgresrepositories.New(staleTx).Evidence.(durableEvidenceRepository)
	loser := expected
	loser.ProductID = productB.ID
	loser.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "product", ID: productB.ID, Relationship: "linked_to"}}
	if err := stale.CompareAndSwapEvidenceLinks(ctx, expected, loser); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale link update error = %v, want conflict", err)
	}
	if err := staleTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback stale transaction: %v", err)
	}

	verifyTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin verify transaction: %v", err)
	}
	defer func() { _ = verifyTx.Rollback(context.Background()) }()
	stored, err := postgresrepositories.New(verifyTx).Evidence.(durableEvidenceRepository).GetEvidence(ctx, tenant.ID, evidence.ID)
	if err != nil {
		t.Fatalf("read committed evidence: %v", err)
	}
	if stored.Title != evidence.Title || stored.ProductID != productA.ID || len(stored.RelatedEvidenceRefs) != 1 || stored.RelatedEvidenceRefs[0].ID != productA.ID {
		t.Fatalf("stale writer replaced winning link: %#v", stored)
	}

	competingTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin competing transaction: %v", err)
	}
	defer func() { _ = competingTx.Rollback(context.Background()) }()
	if _, err := competingTx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		t.Fatalf("set lock timeout: %v", err)
	}
	competing := stored
	competing.ProductID = productB.ID
	competing.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "product", ID: productB.ID, Relationship: "linked_to"}}
	err = postgresrepositories.New(competingTx).Evidence.(durableEvidenceRepository).CompareAndSwapEvidenceLinks(ctx, stored, competing)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "55P03" {
		t.Fatalf("concurrent link mutation error = %v, want evidence row lock timeout", err)
	}
}
