package postgres

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
)

type postgresConcurrentIdempotencyResult struct {
	status   int
	response any
	err      error
}

// TestStoreConcurrentIdempotencyAcrossLedgerInstances uses independent Ledger
// instances sharing only PostgreSQL. This models simultaneous API processes,
// not merely goroutines protected by one process-local transaction gate.
func TestStoreConcurrentIdempotencyAcrossLedgerInstances(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_idempotency_concurrent_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	owner, err := app.NewLedgerWithContext(ctx, app.Config{APIKeyPepper: "test-pepper", Store: store})
	if err != nil {
		t.Fatalf("create owner ledger: %v", err)
	}
	_, _, secret, err := owner.BootstrapTenant(ctx, "PostgreSQL concurrency", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant: %v", err)
	}
	actor, err := owner.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate actor: %v", err)
	}
	product, err := owner.CreateProduct(ctx, actor, "PostgreSQL payments", "postgres-payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := owner.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	var auditsBefore int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = $1`, actor.TenantID).Scan(&auditsBefore); err != nil {
		t.Fatalf("count setup audit entries: %v", err)
	}

	const callers = 16
	ledgers := make([]*app.Ledger, 0, callers)
	for i := 0; i < callers; i++ {
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{APIKeyPepper: "test-pepper", Store: store})
		if err != nil {
			t.Fatalf("create ledger instance %d: %v", i, err)
		}
		ledgers = append(ledgers, ledger)
	}
	ready := make(chan struct{}, callers)
	start := make(chan struct{})
	results := make(chan postgresConcurrentIdempotencyResult, callers)
	body := []byte(`{"release_id":"stable"}`)
	for i := range ledgers {
		ledger := ledgers[i]
		go func() {
			ready <- struct{}{}
			<-start
			status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/release-bundles", "postgres-concurrent-release-bundle", body, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
				bundle, err := commandLedger.CreateReleaseBundle(commandCtx, actor, release.ID)
				return 201, bundle, err
			})
			results <- postgresConcurrentIdempotencyResult{status: status, response: response, err: err}
		}()
	}
	for i := 0; i < callers; i++ {
		<-ready
	}
	close(start)

	var responseID string
	for i := 0; i < callers; i++ {
		result := <-results
		if result.err != nil || result.status != 201 {
			t.Fatalf("postgres concurrent bundle status=%d err=%v", result.status, result.err)
		}
		id := postgresIdempotencyResponseID(t, result.response)
		if responseID == "" {
			responseID = id
		} else if id != responseID {
			t.Fatalf("postgres replay id=%q, want %q", id, responseID)
		}
	}

	counts := map[string]int{}
	for table, query := range map[string]string{
		"products":            `SELECT count(*) FROM products WHERE tenant_id = $1`,
		"release_bundles":     `SELECT count(*) FROM release_bundles WHERE tenant_id = $1`,
		"signatures":          `SELECT count(*) FROM signatures WHERE tenant_id = $1`,
		"outbox_jobs":         `SELECT count(*) FROM outbox_jobs WHERE tenant_id = $1`,
		"idempotency_records": `SELECT count(*) FROM idempotency_records WHERE tenant_id = $1`,
	} {
		var count int
		if err := store.pool.QueryRow(ctx, query, actor.TenantID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		counts[table] = count
	}
	if counts["products"] != 1 || counts["release_bundles"] != 1 || counts["signatures"] != 1 || counts["outbox_jobs"] != 1 || counts["idempotency_records"] != 1 {
		t.Fatalf("postgres concurrent command counts=%#v", counts)
	}
	var auditsAfter int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = $1`, actor.TenantID).Scan(&auditsAfter); err != nil {
		t.Fatalf("count final audit entries: %v", err)
	}
	if auditsAfter-auditsBefore != 1 {
		t.Fatalf("bundle audit delta=%d, want 1", auditsAfter-auditsBefore)
	}
}

func postgresIdempotencyResponseID(t *testing.T, response any) string {
	t.Helper()
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal replay response: %v", err)
	}
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if decoded.ID == "" {
		t.Fatalf("replay response has no id")
	}
	return decoded.ID
}
