package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type failingGovernanceRepository struct{ GovernanceRepository }

func (failingGovernanceRepository) InsertWaiver(context.Context, domain.Waiver) error {
	return errInjectedRepositoryFailure
}

func (failingGovernanceRepository) ApproveWaiver(context.Context, domain.Waiver) error {
	return errInjectedRepositoryFailure
}

func (failingGovernanceRepository) InsertApprovalRecord(context.Context, domain.ApprovalRecord) error {
	return errInjectedRepositoryFailure
}

func (failingGovernanceRepository) InsertRedactionProfile(context.Context, domain.RedactionProfile) error {
	return errInjectedRepositoryFailure
}

func TestGovernanceWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Governance API", "governance-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "sbom", Title: "Governance evidence", PayloadHash: sampleDigest("governance-uow")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	waiver, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "accepted temporarily", Reason: "remediation is tracked", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("create waiver: %v", err)
	}
	waiver, err = ledger.ApproveWaiver(ctx, actor, waiver.ID)
	if err != nil {
		t.Fatalf("approve waiver: %v", err)
	}
	replacement, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "accepted temporarily", Reason: "replacement waiver", ExpiresAt: fixedNow().Add(2 * time.Hour), Supersedes: waiver.ID})
	if err != nil {
		t.Fatalf("supersede waiver: %v", err)
	}
	approval, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{SubjectType: "release", SubjectID: release.ID, Decision: "approved", Reason: "release reviewed", EvidenceID: evidence.ID})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "governance", AllowedTypes: []string{"sbom"}})
	if err != nil {
		t.Fatalf("create redaction profile: %v", err)
	}
	pendingWaiver, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "pending approval", Reason: "exercise approval rollback", ExpiresAt: fixedNow().Add(3 * time.Hour)})
	if err != nil {
		t.Fatalf("create pending waiver: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.Waivers[replacement.ID]; !ok || snapshot.Waivers[waiver.ID].SupersededBy != replacement.ID || snapshot.Approvals[approval.ID].ID == "" || snapshot.RedactionProfiles[profile.ID].ID == "" {
		t.Fatalf("governance writes are not committed together: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Governance = failingGovernanceRepository{GovernanceRepository: repositories.Governance}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failures: %v", err)
	}
	if _, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "failed", Reason: "must not publish", ExpiresAt: fixedNow().Add(time.Hour)}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed waiver write err=%v", err)
	}
	if _, err := ledger.ApproveWaiver(ctx, actor, pendingWaiver.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed waiver approval err=%v", err)
	}
	if _, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{SubjectType: "release", SubjectID: release.ID, Decision: "approved", Reason: "must not publish", EvidenceID: evidence.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed approval write err=%v", err)
	}
	if _, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "failed", AllowedTypes: []string{"sbom"}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed redaction profile write err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(after.Waivers) != len(before.Waivers) || len(after.Approvals) != len(before.Approvals) || len(after.RedactionProfiles) != len(before.RedactionProfiles) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || ledger.waivers[pendingWaiver.ID].Approved {
		t.Fatalf("governance repository failure published state: before=%#v after=%#v", before, after)
	}
}
