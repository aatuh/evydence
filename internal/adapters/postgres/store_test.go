package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreLoadSaveAndOutboxWithPostgres(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	state := app.PersistedState{
		Tenants: map[string]domain.Tenant{
			"ten_test": {ID: "ten_test", Name: "Test", CreatedAt: time.Now().UTC()},
		},
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Tenants["ten_test"].ID != "ten_test" {
		t.Fatalf("unexpected loaded state: ok=%v state=%#v", ok, got.Tenants)
	}
	job := app.OutboxJob{ID: "job_test_" + time.Now().Format("150405.000000000"), TenantID: "ten_test", Kind: "verify_subject", SubjectType: "audit_chain", SubjectID: "audit_chain", CreatedAt: time.Now().UTC()}
	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ClaimJobs(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 {
		t.Fatal("expected claimed job")
	}
	if err := store.CompleteJob(ctx, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
}
