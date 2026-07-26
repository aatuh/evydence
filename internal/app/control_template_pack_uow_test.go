package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingTemplatePackControlRepository struct{ ControlRepository }

func (failingTemplatePackControlRepository) InsertSecurityControl(context.Context, domain.SecurityControl) error {
	return errInjectedRepositoryFailure
}

func TestTemplatePackInstallationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	pack := builtinTemplatePacks()[0]
	auditEntriesBefore := len(ledger.chain[actor.TenantID])

	framework, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, pack.Slug)
	if err != nil {
		t.Fatalf("install template pack: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after template pack install: %v", err)
	}
	if _, ok := snapshot.ControlFrameworks[framework.ID]; !ok || len(snapshot.SecurityControls) != len(pack.Controls) || len(snapshot.AuditEntries[actor.TenantID]) != auditEntriesBefore+1 {
		t.Fatalf("template pack was not committed atomically: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Controls = failingTemplatePackControlRepository{ControlRepository: repositories.Controls}
		return repositories
	}}
	beforeFrameworks, beforeControls, beforeAudit := len(ledger.frameworks), len(ledger.controls), len(ledger.chain[actor.TenantID])
	if _, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, builtinTemplatePacks()[1].Slug); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed template pack install err=%v, want injected repository failure", err)
	}
	if len(ledger.frameworks) != beforeFrameworks || len(ledger.controls) != beforeControls || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed template pack install published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed template pack install: %v", err)
	}
	if len(after.ControlFrameworks) != len(snapshot.ControlFrameworks) || len(after.SecurityControls) != len(snapshot.SecurityControls) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed template pack install published durable state: before=%#v after=%#v", snapshot, after)
	}
}
