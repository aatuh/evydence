package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

func TestWorkerLoopShutdownPostgresLeaseReclaimAndNativeIdempotency(t *testing.T) {
	baseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	for _, mode := range []string{"graceful", "canceled-before-effect", "committed-before-timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			admin, err := pgx.Connect(ctx, baseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer admin.Close(context.WithoutCancel(ctx))
			schema := "evydence_worker_drain_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
			quoted := pgx.Identifier{schema}.Sanitize()
			if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer cancel()
				if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
					t.Error(err)
				}
			}()
			url := postgresURLWithSearchPath(t, baseURL, schema)
			store, err := postgres.Open(ctx, url)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err = store.ApplyMigrations(ctx, "../../migrations"); err != nil {
				t.Fatal(err)
			}
			conn, err := pgx.Connect(ctx, url)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(context.WithoutCancel(ctx))
			if _, err = conn.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Drain'); INSERT INTO ledger_state(id,state)VALUES('default','"aggregate-forbidden"')`); err != nil {
				t.Fatal(err)
			}
			objects, err := filesystem.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			native, err := newNativeJobProcessor(store, objects, defaultMaxWorkerPayloadBytes)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("worker-drain-native-payload")
			digest := digestBytes(data)
			hex := strings.TrimPrefix(digest, "sha256:")
			now := time.Now().UTC()
			payload := app.ObjectPayload{TenantID: "tenant", Digest: digest, Size: int64(len(data)), MediaType: "text/plain", StagingKey: "tenants/tenant/staging/sha256/" + hex, FinalKey: "tenants/tenant/payloads/sha256/" + hex, Status: app.ObjectPayloadStaged, CreatedAt: now, UpdatedAt: now}
			payload, err = objects.StagePayload(ctx, payload, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			uow, err := store.BeginUnitOfWork(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = uow.Rollback(context.WithoutCancel(ctx)) }()
			if err = uow.Repositories().Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
				t.Fatal(err)
			}
			if err = uow.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			job := app.OutboxJob{ID: "drain-job", TenantID: "tenant", Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: digest, Payload: map[string]any{"payload_digest": digest}, CreatedAt: now}
			if err = store.Enqueue(ctx, job); err != nil {
				t.Fatal(err)
			}
			root, stop := context.WithCancel(ctx)
			defer stop()
			var first postgres.ClaimedJob
			finished := make(chan struct{})
			processor := lifecycleProcessor(func(jobCtx context.Context, claimed postgres.ClaimedJob) error {
				defer close(finished)
				first = claimed
				if mode != "canceled-before-effect" {
					if err := native.Process(jobCtx, claimed); err != nil {
						return err
					}
				}
				stop()
				if mode != "graceful" {
					<-jobCtx.Done()
					return jobCtx.Err()
				}
				return nil
			})
			config := shutdownLoopConfig()
			config.BatchSize = 1
			config.ShutdownTimeout = 20 * time.Millisecond
			err = runWorkerLoop(root, store, processor, config)
			<-finished
			if mode == "graceful" && err != nil {
				t.Fatal("native graceful drain failed", err)
			}
			if mode != "graceful" && !errors.Is(err, errWorkerDrainTimeout) {
				t.Fatal("unfinished native job did not fail safely", err)
			}
			var status string
			var attempts, successes int
			if err = conn.QueryRow(ctx, `SELECT status,attempts FROM outbox_jobs WHERE id='drain-job'`).Scan(&status, &attempts); err != nil {
				t.Fatal(err)
			}
			if attempts != 1 {
				t.Fatal("unexpected claims", attempts)
			}
			if mode == "graceful" {
				if status != "succeeded" {
					t.Fatal("drained job not complete", status)
				}
			} else {
				if status != "running" {
					t.Fatal("unfinished job falsely acknowledged", status)
				}
				var outcomes int
				if err = conn.QueryRow(ctx, `SELECT count(*) FROM outbox_job_attempts WHERE outcome <> 'claimed'`).Scan(&outcomes); err != nil || outcomes != 0 {
					t.Fatal("unfinished outcome was recorded", outcomes, err)
				}
				// Advance only this isolated fixture's lease timestamp; no wall-clock
				// sleep or production lease-duration override is needed.
				if _, err = conn.Exec(ctx, `UPDATE outbox_jobs SET locked_at=now()-interval '6 minutes' WHERE id='drain-job'`); err != nil {
					t.Fatal(err)
				}
				reclaimed, err := store.ClaimJobs(ctx, 1)
				if err != nil || len(reclaimed) != 1 {
					t.Fatal("unfinished lease not reclaimable", reclaimed, err)
				}
				current := reclaimed[0]
				if current.TenantID != "tenant" || current.Attempts != 2 || current.LeaseToken == first.LeaseToken || current.LeaseToken == "" {
					t.Fatal("reclaim lost ownership/fencing")
				}
				if err = store.CompleteJob(ctx, first.ID, first.LeaseToken); !errors.Is(err, app.ErrConflict) {
					t.Fatal("stale worker completed new lease", err)
				}
				for range 2 {
					if err = native.Process(ctx, current); err != nil {
						t.Fatal("native retry not idempotent", err)
					}
				}
				if err = store.CompleteJob(ctx, current.ID, current.LeaseToken); err != nil {
					t.Fatal(err)
				}
				if err = store.CompleteJob(ctx, current.ID, current.LeaseToken); !errors.Is(err, app.ErrConflict) {
					t.Fatal("duplicate acknowledgement accepted", err)
				}
			}
			if err = conn.QueryRow(ctx, `SELECT count(*) FROM outbox_job_attempts WHERE outcome='succeeded'`).Scan(&successes); err != nil || successes != 1 {
				t.Fatal("completion was not exactly once", successes, err)
			}
			stored, err := store.GetObjectPayload(ctx, "tenant", digest)
			if err != nil || stored.Status != app.ObjectPayloadFinalized {
				t.Fatal("retry did not finalize", stored, err)
			}
			got, err := objects.GetBounded(ctx, payload.FinalKey, int64(len(data)))
			if err != nil || !bytes.Equal(got.Bytes, data) {
				t.Fatal("native payload changed", err)
			}
			if _, err = store.GetObjectPayload(ctx, "other", digest); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("foreign tenant payload visible", err)
			}
			if _, _, err = store.LoadState(ctx); err == nil {
				t.Fatal("native loop replaced aggregate canary")
			}
		})
	}
}
