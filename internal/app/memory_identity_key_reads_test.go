package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestMemoryAPIKeyTenantGuardRejectsUnknownCanceledAndClosedTransactions(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	if err := ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Tenant", CreatedAt: fixedNow()})
	}); err != nil {
		t.Fatal(err)
	}
	uow, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := uow.Repositories().Identity.(identityapp.APIKeyWriteReader)
	if !ok {
		t.Fatal("memory identity repository lacks scoped API-key reads")
	}
	if err := reader.LockAPIKeyCreation(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	if err := reader.LockAPIKeyCreation(t.Context(), "unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant guard accepted unknown ownership", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reader.LockAPIKeyCreation(ctx, "tenant"); !errors.Is(err, context.Canceled) {
		t.Fatal("tenant guard ignored cancellation", err)
	}
	if err := uow.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := reader.LockAPIKeyCreation(t.Context(), "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("tenant guard retained a closed transaction", err)
	}
}
