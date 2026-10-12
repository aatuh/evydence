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

func TestTemplatePackInstallationRecordsHumanAuditIdentity(t *testing.T) {
	for _, transactional := range []bool{true, false} {
		name := "maps"
		if transactional {
			name = "memory_transaction"
		}
		t.Run(name, func(t *testing.T) {
			memory := NewMemoryUnitOfWorkFactory()
			ledger, _, owner := newReleaseEvidenceUnitOfWorkFixture(t, memory)
			if !transactional {
				ledger.unitOfWork = nil
			}
			human := domain.Actor{TenantID: owner.TenantID, UserID: "reviewer", Scopes: []string{ScopeControlsAdmin}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.TenantID, Scopes: []string{ScopeControlsAdmin}}}}
			before := len(ledger.chain[owner.TenantID])
			framework, err := ledger.InstallControlFrameworkTemplatePack(t.Context(), human, builtinTemplatePacks()[0].Slug)
			if err != nil {
				t.Fatal("human template installation:", err)
			}
			entries := ledger.chain[owner.TenantID]
			if len(entries) != before+1 {
				t.Fatal("installation did not append exactly one audit entry")
			}
			entry := entries[len(entries)-1]
			if transactional {
				snapshot, err := memory.Snapshot()
				if err != nil || len(snapshot.AuditEntries[owner.TenantID]) != before+1 {
					t.Fatal("human installation audit not committed:", err)
				}
				entry = snapshot.AuditEntries[owner.TenantID][before]
			}
			if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.SubjectType != "control_framework" || entry.SubjectID != framework.ID || entry.EntryType != "control_framework_template.installed" {
				t.Fatal("template installation lost the actual human audit identity", entry)
			}
		})
	}
}
