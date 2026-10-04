package repositories_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
)

func TestIdempotencyRepositoryRestartReplayPreservesExactJSONNumbers(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	now := time.Now().UTC()
	key := app.IdempotencyRecordKey{TenantID: "tenant_exact_numbers", ActorID: "api_key:key", Method: "POST", Path: "/v1/customer-packages", IdempotencyKey: "exact-numbers"}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES($1,'Exact numbers')`, key.TenantID); err != nil {
		t.Fatal(err)
	}
	reservation := app.IdempotencyReservation{Key: key, RequestHash: "sha256:request", OwnerTokenHash: "sha256:owner", Now: now, LeaseExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	repo := postgresrepositories.New(tx).Idempotency
	if result, err := repo.Reserve(ctx, reservation); err != nil || result.Outcome != app.IdempotencyReservationAcquired {
		t.Fatal("reserve", result.Outcome, err)
	}
	const numbers = `{"size":9007199254740993,"max":9223372036854775807,"min":-9223372036854775808,"decimal":0.12345678901234567890123456789,"nested":[9007199254740995]}`
	if err := repo.Complete(ctx, key, reservation.OwnerTokenHash, 201, json.RawMessage(numbers), now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Rollback(context.WithoutCancel(ctx)) }()
	result, err := postgresrepositories.New(restarted).Idempotency.Reserve(ctx, reservation)
	if err != nil || result.Outcome != app.IdempotencyReservationReplay || result.Record.Status != 201 {
		t.Fatal("restart did not replay", err)
	}
	body, err := json.Marshal(result.Record.Response)
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []string{"9007199254740993", "9223372036854775807", "-9223372036854775808", "0.12345678901234567890123456789", "9007199254740995"} {
		if !strings.Contains(string(body), number) {
			t.Fatal("durable replay changed exact number", number, string(body))
		}
	}
}
