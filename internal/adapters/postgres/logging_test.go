package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func loggingStoreFixture(t *testing.T) (*Store, context.Context, *bytes.Buffer) {
	t.Helper()
	store := isolatedRelationalTestStore(t)
	out := &bytes.Buffer{}
	logger, err := logging.New(out, "api", runtimeinfo.Current(), logging.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := logging.WithOperation(logging.WithRequest(logging.WithLogger(t.Context(), logger), "CANARY_REQUEST"), "ingestEvidence")
	u, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_logging", Name: "CANARY_CUSTOMER_NAME", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := u.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	return store, ctx, out
}

func TestAuditLoggingPublishesOnlyCommittedReceipts(t *testing.T) {
	store, ctx, out := loggingStoreFixture(t)
	entry := domain.AuditChainEntry{ID: "ace_logging", TenantID: "ten_logging", EntryType: "logging.test", SubjectType: "evidence", SubjectID: "CANARY_RESOURCE", ActorType: "system", ActorID: "CANARY_ACTOR", OccurredAt: time.Now().UTC(), Metadata: map[string]any{"raw": "CANARY_PAYLOAD"}}
	u, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := u.Repositories().Audit.Append(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("uncommitted audit reported as durable")
	}
	if err := u.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "CANARY") {
		t.Fatal("audit content leaked")
	}
	seen := 0
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r["msg"] == "audit" {
			seen++
			if r["receipt_id"] != logging.Reference("receipt", receipt.ID) || r["request_id"] != logging.CorrelationFromContext(ctx).RequestID || r["result_code"] != "succeeded" {
				t.Fatal("audit receipt correlation lost")
			}
		}
	}
	if seen != 1 {
		t.Fatalf("durable audit events=%d", seen)
	}
	out.Reset()
	rolled, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entry.ID = "ace_rolled_back"
	if _, err := rolled.Repositories().Audit.Append(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err := rolled.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"msg":"audit"`) {
		t.Fatal("rolled-back audit logged as committed")
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries`).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit transaction behavior changed", count, err)
	}
}

func TestOutboxCorrelationIsAtomicAndDoesNotAlterPayloadOrDeduplication(t *testing.T) {
	store, ctx, _ := loggingStoreFixture(t)
	payload := map[string]any{"private_payload": "CANARY_RAW_EVIDENCE", "parser_version": "fixture.v1"}
	job := app.OutboxJob{ID: "job_logging", TenantID: "ten_logging", Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: "object_logging", Payload: payload, CreatedAt: time.Now().UTC()}
	u, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Repositories().Outbox.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := u.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	duplicate := job
	duplicate.ID = "job_duplicate"
	second := logging.WithRequest(ctx, "other_request")
	if err := store.Enqueue(second, duplicate); err != nil {
		t.Fatal(err)
	}
	var requestID, operationID string
	var raw []byte
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT log_request_id,log_operation_id,payload FROM outbox_jobs WHERE id=$1`, job.ID).Scan(&requestID, &operationID, &raw); err != nil {
		t.Fatal(err)
	}
	correlation := logging.CorrelationFromContext(ctx)
	if requestID != correlation.RequestID || operationID != correlation.OperationID {
		t.Fatal("enqueue correlation lost or overwritten by duplicate")
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 || saved["private_payload"] != "CANARY_RAW_EVIDENCE" {
		t.Fatal("logging changed durable payload")
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("logging changed deduplication", count, err)
	}
	rolled, err := store.BeginUnitOfWork(second)
	if err != nil {
		t.Fatal(err)
	}
	job.ID = "job_rolled"
	job.SubjectID = "other_object"
	if err := rolled.Repositories().Outbox.Enqueue(second, job); err != nil {
		t.Fatal(err)
	}
	if err := rolled.Rollback(second); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE id=$1`, job.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rolled-back correlation escaped transaction")
	}
	claimed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Correlation != correlation {
		t.Fatal("claim lost durable correlation", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET log_request_id='CANARY_SECRET'`); err == nil {
		t.Fatal("raw correlation bypassed database constraint")
	}
}

func TestAuditLoggingDoesNotPublishSuccessAfterFailedCommit(t *testing.T) {
	store, ctx, out := loggingStoreFixture(t)
	_, err := store.pool.Exec(ctx, `CREATE FUNCTION refuse_logging_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'CANARY_PRIVATE_DATABASE_ERROR'; END $$;
 CREATE CONSTRAINT TRIGGER refuse_logging_commit AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_logging_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	u, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.Repositories().Audit.Append(ctx, domain.AuditChainEntry{ID: "ace_failed_commit", TenantID: "ten_logging", EntryType: "logging.test", SubjectType: "evidence", SubjectID: "CANARY_RESOURCE", ActorType: "system", ActorID: "system", OccurredAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Commit(ctx); err == nil {
		t.Fatal("deferred commit failure was ignored")
	}
	_ = u.Rollback(ctx)
	if strings.Contains(out.String(), "CANARY") || strings.Contains(out.String(), `"msg":"audit"`) || !strings.Contains(out.String(), `"result_code":"uncertain"`) {
		t.Fatal("failed commit produced a false or unsafe receipt")
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed commit persisted audit")
	}
}

func TestPostgresOutboxCorrelationMigrationPreservesExistingJobs(t *testing.T) {
	store, ctx, _ := loggingStoreFixture(t)
	execute := func(direction string) {
		t.Helper()
		sql, err := os.ReadFile("../../../migrations/20261016000100_outbox_log_correlation." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	execute("down")
	if _, err := store.pool.Exec(ctx, `INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,deduplication_key,payload,status)VALUES('job_old','ten_logging','parse_sbom','sbom','old','sha256:old','{"source":"CANARY_OLD_PAYLOAD"}','queued')`); err != nil {
		t.Fatal(err)
	}
	execute("up")
	var request, operation, state, payload string
	if err := store.pool.QueryRow(ctx, `SELECT log_request_id,log_operation_id,status,payload->>'source' FROM outbox_jobs WHERE id='job_old'`).Scan(&request, &operation, &state, &payload); err != nil || request != "" || operation != "" || state != "queued" || payload != "CANARY_OLD_PAYLOAD" {
		t.Fatal("upgrade changed existing job", err)
	}
	execute("down")
	if err := store.pool.QueryRow(ctx, `SELECT status,payload->>'source' FROM outbox_jobs WHERE id='job_old'`).Scan(&state, &payload); err != nil || state != "queued" || payload != "CANARY_OLD_PAYLOAD" {
		t.Fatal("downgrade changed job", err)
	}
	execute("up")
}
