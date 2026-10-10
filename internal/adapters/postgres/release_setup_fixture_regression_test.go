package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

// This proves the outer fixture's transaction composition with the real memory
// test backend, not PostgreSQL locks, durability or backup/restore behavior.
func TestPostgresReleaseSetupFixtureUsesCurrentRowsAndCallerReplayTransaction(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	ledger, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{APIKeyPepper: "fixture", UnitOfWork: base})
	if err != nil {
		t.Fatal(err)
	}
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("release setup used aggregate clock") }})
	if err != nil {
		t.Fatal(err)
	}
	f := postgresReleaseSetup(cold)
	product, err := f.CreateProduct(t.Context(), actor, "Original", "original")
	if err != nil || product.ID == "" {
		t.Fatal("cold product setup failed", err)
	}
	release, err := f.CreateRelease(t.Context(), actor, product.ID, "1")
	if err != nil || release.ProductID != product.ID || release.State != "draft" || release.Revision != 1 {
		t.Fatal("release setup used stale catalog parents", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	artifact, err := f.RegisterArtifact(t.Context(), actor, "Original", "application/octet-stream", digest, 9007199254740993)
	if err != nil || artifact.Size != 9007199254740993 {
		t.Fatal("artifact setup lost exact integer size", err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := f.RegisterArtifact(t.Context(), actor, "Replacement", "changed", digest, 1)
	if err != nil || !reflect.DeepEqual(duplicate, artifact) {
		t.Fatal("artifact setup changed immutable natural-key identity", err)
	}
	denied := actor
	denied.KeyID, denied.UserID = "", "human"
	denied.ResourceGrants = nil
	if v, err := f.RegisterArtifact(t.Context(), denied, "Denied", "changed", digest, 1); !errors.Is(err, application.ErrForbidden) || v != (domain.Artifact{}) {
		t.Fatal("denied duplicate exposed private metadata or returned the wrong error", err)
	}
	reused, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, reused) {
		t.Fatal("duplicate or denied setup wrote effects", err)
	}
	want := errors.New("fixture outer transaction rollback")
	_, _, err = ledger.WithIdempotency(t.Context(), actor, "POST", "/v1/products", "fixture-rollback", []byte(`{"name":"Pending","slug":"pending"}`), func(ctx context.Context, commandLedger *app.Ledger) (int, any, error) {
		commands := postgresReleaseSetup(commandLedger)
		pending, err := commands.CreateProduct(ctx, actor, "Pending", "pending")
		if err != nil {
			return 0, nil, err
		}
		if _, err := commands.CreateRelease(ctx, actor, pending.ID, "1"); err != nil {
			return 0, nil, err
		}
		return 500, nil, want
	})
	if !errors.Is(err, want) {
		t.Fatal("fixture failed to join caller's active transaction", err)
	}
	after, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Idempotency) != len(before.Idempotency)+1 {
		t.Fatal("failed caller replay state was not recorded")
	}
	for _, record := range after.Idempotency {
		if record.State != "failed" {
			t.Fatal("failed compound transaction retained successful replay state")
		}
	}
	// Failed replay status is intentional; all catalog/audit effects must roll back.
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("nested setup escaped the caller's transaction rollback")
	}
}
