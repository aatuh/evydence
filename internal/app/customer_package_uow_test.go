package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type failingCustomerPackageRepository struct{ PackageRepository }

func (failingCustomerPackageRepository) InsertCustomerSecurityPackage(context.Context, domain.CustomerSecurityPackage) error {
	return errInjectedRepositoryFailure
}

func (failingCustomerPackageRepository) UpdateCustomerSecurityPackageAccess(context.Context, domain.CustomerSecurityPackage, domain.CustomerSecurityPackage) error {
	return errInjectedRepositoryFailure
}

func TestCustomerPackageWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Customer packages", "customer-packages")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"sbom"}})
	if err != nil {
		t.Fatalf("create redaction profile: %v", err)
	}
	auditEntriesBefore := len(ledger.chain[actor.TenantID])
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: product.ID, RedactionProfileID: profile.ID, Title: "Customer package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("create customer security package: %v", err)
	}
	accessed, err := ledger.AccessCustomerSecurityPackage(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("access customer security package: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after customer package writes: %v", err)
	}
	if snapshot.CustomerPackages[pkg.ID].AccessCount != accessed.AccessCount || accessed.AccessCount != 1 || len(snapshot.AuditEntries[actor.TenantID]) != auditEntriesBefore+2 {
		t.Fatalf("customer package writes were not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Packages = failingCustomerPackageRepository{PackageRepository: repositories.Packages}
		return repositories
	}}
	beforePackages, beforeAudit := len(ledger.customerPackages), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: product.ID, RedactionProfileID: profile.ID, Title: "Failed customer package", ExpiresAt: fixedNow().Add(2 * time.Hour)}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed customer package create err=%v, want injected repository failure", err)
	}
	if _, err := ledger.AccessCustomerSecurityPackage(ctx, actor, pkg.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed customer package access err=%v, want injected repository failure", err)
	}
	if len(ledger.customerPackages) != beforePackages || len(ledger.chain[actor.TenantID]) != beforeAudit || ledger.customerPackages[pkg.ID].AccessCount != accessed.AccessCount {
		t.Fatal("failed customer package write published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed customer package writes: %v", err)
	}
	if len(after.CustomerPackages) != len(snapshot.CustomerPackages) || after.CustomerPackages[pkg.ID].AccessCount != snapshot.CustomerPackages[pkg.ID].AccessCount || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed customer package write published durable state: before=%#v after=%#v", snapshot, after)
	}
}
