package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingDSSETrustRootRepository struct{ GovernanceRepository }

func (failingDSSETrustRootRepository) InsertDSSETrustRoot(context.Context, domain.DSSETrustRoot) error {
	return errInjectedRepositoryFailure
}

func TestDSSETrustRootUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	auditEntriesBefore := len(ledger.chain[actor.TenantID])

	root, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "Root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: publicKey})
	if err != nil {
		t.Fatalf("create DSSE trust root: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after DSSE trust root: %v", err)
	}
	if snapshot.DSSETrustRoots[root.ID].ID != root.ID || len(snapshot.AuditEntries[actor.TenantID]) != auditEntriesBefore+1 {
		t.Fatalf("DSSE trust root was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Governance = failingDSSETrustRootRepository{GovernanceRepository: repositories.Governance}
		return repositories
	}}
	beforeRoots, beforeAudit := len(ledger.dsseTrustRoots), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "Failed", KeyID: "root-2", Algorithm: "Ed25519", PublicKey: publicKey}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed DSSE trust root err=%v, want injected repository failure", err)
	}
	if len(ledger.dsseTrustRoots) != beforeRoots || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed DSSE trust root published cached state")
	}

	uow, err := memory.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin DSSE trust root validation unit of work: %v", err)
	}
	defer func() { _ = uow.Rollback(context.Background()) }()
	repositories := uow.Repositories()
	duplicate := root
	duplicate.ID = "dsse_trust_root_duplicate"
	if err := repositories.Governance.InsertDSSETrustRoot(ctx, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate DSSE trust root err=%v, want conflict", err)
	}
	invalid := root
	invalid.ID = "dsse_trust_root_invalid"
	invalid.PublicKey = "not-base64"
	if err := repositories.Governance.InsertDSSETrustRoot(ctx, invalid); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid DSSE trust root err=%v, want validation", err)
	}
}
