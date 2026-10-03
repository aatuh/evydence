package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresSigningKeyLifecyclePersistsHistoryAndSerializesActiveKeys(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_signing_lifecycle_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") }()
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_signing_lifecycle", Name: "Signing lifecycle", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	firstKey := domain.SigningKey{ID: "key_signing_lifecycle_1", TenantID: "ten_signing_lifecycle", KID: "20260815T120000Z-v1", Version: 1, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: "public-one", PublicKeyFingerprint: "sha256:one", ValidFrom: now, CreatedAt: now, HistoricalValidityPolicy: domain.SigningKeyHistoricalValidityPreserve}
	first, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Rollback(context.Background()) }()
	if err := first.Repositories().Signatures.InsertSigningKey(ctx, firstKey); err != nil {
		t.Fatal(err)
	}

	second, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Rollback(context.Background()) }()
	secondResult := make(chan error, 1)
	go func() {
		secondKey := firstKey
		secondKey.ID = "key_signing_lifecycle_conflict"
		secondKey.KID = "20260815T120000Z-v2"
		secondKey.Version = 2
		secondResult <- second.Repositories().Signatures.InsertSigningKey(ctx, secondKey)
	}()
	select {
	case err := <-secondResult:
		t.Fatalf("concurrent active key insert returned before first commit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatalf("commit first key: %v", err)
	}
	if err := <-secondResult; !errors.Is(err, app.ErrConflict) {
		t.Fatalf("concurrent active key insert err=%v, want conflict", err)
	}
	if err := second.Rollback(ctx); err != nil {
		t.Fatalf("rollback conflicting key: %v", err)
	}

	rotatedAt := now.Add(time.Hour)
	transition, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transition.Rollback(context.Background()) }()
	firstKey.Status = domain.SigningKeyStatusRetiring
	firstKey.ValidUntil = &rotatedAt
	if err := transition.Repositories().Signatures.UpdateSigningKey(ctx, firstKey, domain.SigningKeyStatusActive); err != nil {
		t.Fatalf("retire first key: %v", err)
	}
	secondKey := domain.SigningKey{ID: "key_signing_lifecycle_2", TenantID: firstKey.TenantID, KID: "20260815T130000Z-v2", Version: 2, Provider: firstKey.Provider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: "public-two", PublicKeyFingerprint: "sha256:two", ValidFrom: rotatedAt, CreatedAt: rotatedAt, HistoricalValidityPolicy: domain.SigningKeyHistoricalValidityPreserve}
	if err := transition.Repositories().Signatures.InsertSigningKey(ctx, secondKey); err != nil {
		t.Fatalf("insert replacement key: %v", err)
	}
	if err := transition.Commit(ctx); err != nil {
		t.Fatalf("commit rotation: %v", err)
	}

	var version int
	var provider, fingerprint, status string
	var validFrom, validUntil time.Time
	if err := store.pool.QueryRow(ctx, `SELECT version, provider, public_key_fingerprint, status, valid_from, valid_until FROM signing_keys WHERE id = $1`, firstKey.ID).Scan(&version, &provider, &fingerprint, &status, &validFrom, &validUntil); err != nil {
		t.Fatalf("read retired signing key: %v", err)
	}
	if version != 1 || provider != domain.SigningKeyDefaultProvider || fingerprint != "sha256:one" || status != domain.SigningKeyStatusRetiring || !validFrom.Equal(now) || !validUntil.Equal(rotatedAt) {
		t.Fatalf("retired signing key lifecycle version=%d provider=%q fingerprint=%q status=%q valid_from=%s valid_until=%s", version, provider, fingerprint, status, validFrom, validUntil)
	}
}
