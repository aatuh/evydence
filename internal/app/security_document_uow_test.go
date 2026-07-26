package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingSecurityDocumentRepository struct{ RiskRepository }

func (failingSecurityDocumentRepository) InsertSecurityScan(context.Context, domain.SecurityScan) error {
	return errInjectedRepositoryFailure
}

func (failingSecurityDocumentRepository) InsertManualSecurityDocument(context.Context, domain.ManualSecurityDocument) error {
	return errInjectedRepositoryFailure
}

func TestSecurityScanAndManualDocumentUseUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Security evidence", "security-evidence")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "service", "application/octet-stream", sampleDigest("security-document"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	scan, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{ProductID: product.ID, ReleaseID: release.ID, ArtifactID: artifact.ID, Category: "sast", Format: "sarif", Scanner: "codeql", TargetRef: "git:main", Raw: []byte(`{"version":"2.1.0","runs":[{"results":[{"level":"error"}]}]}`)})
	if err != nil {
		t.Fatalf("upload security scan: %v", err)
	}
	document, err := ledger.UploadManualSecurityDocument(ctx, actor, UploadManualSecurityDocumentInput{ProductID: product.ID, ReleaseID: release.ID, DocumentType: "security_review", Title: "Review", Sensitivity: "restricted", Raw: []byte("review"), MediaType: "text/plain"})
	if err != nil {
		t.Fatalf("upload manual security document: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after security documents: %v", err)
	}
	if snapshot.SecurityScans[scan.ID].ID != scan.ID || snapshot.ManualSecurityDocuments[document.ID].ID != document.ID || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+4 {
		t.Fatalf("security-document writes were not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Risk = failingSecurityDocumentRepository{RiskRepository: repositories.Risk}
		return repositories
	}}
	beforeScans, beforeDocuments := len(ledger.securityScans), len(ledger.manualDocs)
	if _, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{ProductID: product.ID, ReleaseID: release.ID, Category: "sast", Format: "sarif", Scanner: "codeql", TargetRef: "git:main", Raw: []byte(`{"version":"2.1.0","runs":[]}`)}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed security scan err=%v, want injected repository failure", err)
	}
	if _, err := ledger.UploadManualSecurityDocument(ctx, actor, UploadManualSecurityDocumentInput{ProductID: product.ID, ReleaseID: release.ID, DocumentType: "security_review", Title: "Failed review", Sensitivity: "restricted", Raw: []byte("review")}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed manual security document err=%v, want injected repository failure", err)
	}
	if len(ledger.securityScans) != beforeScans || len(ledger.manualDocs) != beforeDocuments {
		t.Fatal("failed security-document write published derived cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed security documents: %v", err)
	}
	if len(after.SecurityScans) != len(snapshot.SecurityScans) || len(after.ManualSecurityDocuments) != len(snapshot.ManualSecurityDocuments) {
		t.Fatalf("failed security-document write published derived durable state: before=%#v after=%#v", snapshot, after)
	}
}
