package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingControlRepository struct{ ControlRepository }

func (failingControlRepository) InsertControlFramework(context.Context, domain.ControlFramework) error {
	return errInjectedRepositoryFailure
}

func (failingControlRepository) InsertSecurityControl(context.Context, domain.SecurityControl) error {
	return errInjectedRepositoryFailure
}

func (failingControlRepository) InsertControlEvidence(context.Context, domain.ControlEvidence) error {
	return errInjectedRepositoryFailure
}

func TestControlWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Controls API", "controls-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	framework, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Controls", Slug: "controls", Version: "1"})
	if err != nil {
		t.Fatalf("create framework: %v", err)
	}
	control, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{
		FrameworkID:          framework.ID,
		Code:                 "CTRL-1",
		Title:                "Evidence is recorded",
		Objective:            "Record release evidence.",
		EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "sbom", Required: true}},
	})
	if err != nil {
		t.Fatalf("create security control: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "sbom", Title: "Control evidence", PayloadHash: sampleDigest("control-uow")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	link, err := ledger.LinkControlEvidence(ctx, actor, control.ID, LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "evidence", SubjectID: evidence.ID, ProductID: product.ID, ReleaseID: release.ID, Confidence: confidenceHigh})
	if err != nil {
		t.Fatalf("link control evidence: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.ControlFrameworks[framework.ID]; !ok {
		t.Fatalf("framework is not committed: %#v", snapshot)
	}
	if _, ok := snapshot.SecurityControls[control.ID]; !ok {
		t.Fatalf("control is not committed: %#v", snapshot)
	}
	if _, ok := snapshot.ControlEvidence[link.ID]; !ok {
		t.Fatalf("control evidence is not committed: %#v", snapshot)
	}
	secondControl, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{
		FrameworkID: framework.ID,
		Code:        "CTRL-2",
		Title:       "A second control",
		Objective:   "Exercise a distinct evidence link.",
	})
	if err != nil {
		t.Fatalf("create second security control: %v", err)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Controls = failingControlRepository{ControlRepository: repositories.Controls}
		return repositories
	}}
	beforeRepositoryFailure, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before repository failures: %v", err)
	}
	if _, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Repository failed", Slug: "repository-failed", Version: "1"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed framework write err=%v", err)
	}
	if _, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{FrameworkID: framework.ID, Code: "CTRL-FAIL", Title: "Repository failed", Objective: "Must not publish."}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed control write err=%v", err)
	}
	if _, err := ledger.LinkControlEvidence(ctx, actor, secondControl.ID, LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "evidence", SubjectID: evidence.ID, ProductID: product.ID, ReleaseID: release.ID, Confidence: confidenceHigh}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed control evidence write err=%v", err)
	}
	afterRepositoryFailure, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after repository failures: %v", err)
	}
	if len(afterRepositoryFailure.ControlFrameworks) != len(beforeRepositoryFailure.ControlFrameworks) || len(afterRepositoryFailure.SecurityControls) != len(beforeRepositoryFailure.SecurityControls) || len(afterRepositoryFailure.ControlEvidence) != len(beforeRepositoryFailure.ControlEvidence) || len(afterRepositoryFailure.AuditEntries[actor.TenantID]) != len(beforeRepositoryFailure.AuditEntries[actor.TenantID]) {
		t.Fatalf("control repository failure published state: before=%#v after=%#v", beforeRepositoryFailure, afterRepositoryFailure)
	}

	ledger.unitOfWork = commitFailingUnitOfWorkFactory{inner: memory}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed write: %v", err)
	}
	if _, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Uncommitted", Slug: "uncommitted", Version: "1"}); err == nil {
		t.Fatal("expected commit failure")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed write: %v", err)
	}
	if len(after.ControlFrameworks) != len(before.ControlFrameworks) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed control write published durable state: before=%#v after=%#v", before, after)
	}
	for id, stored := range ledger.frameworks {
		if stored.Slug == "uncommitted" {
			t.Fatalf("failed control write published cache entry %q", id)
		}
	}
}
