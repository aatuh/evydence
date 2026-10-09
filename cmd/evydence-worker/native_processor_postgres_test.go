package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

func TestNativeWorkerPostgresNeverLoadsAggregateAndFinalizesPayload(t *testing.T) {
	baseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.WithoutCancel(ctx))
	schema := "evydence_native_worker_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
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
	if _, err := store.ApplyMigrations(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	_, err = conn.Exec(ctx, `INSERT INTO ledger_state(id,state)VALUES('default','"native-worker-aggregate-forbidden"');
INSERT INTO tenants(id,name)VALUES('tenant','Native'),('other','Other');
INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Native','native');
INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft');
INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)VALUES('evidence','tenant','product','release','sbom','Source','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L1','pending');
INSERT INTO sboms(id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components)VALUES('sbom','tenant','evidence','release','cyclonedx','1.6',0,'[]');
INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs)VALUES('bundle','tenant','release','published','{}','sha256:fixture','["recorded-reference"]');
INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,verified_at)VALUES('result','tenant','evidence_item','evidence','failed','[]',now());`)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadState(ctx); err == nil {
		t.Fatal("worker aggregate canary not active")
	}
	objects, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := newNativeJobProcessor(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	jobs := []postgres.ClaimedJob{
		{ID: "parsed", TenantID: "tenant", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "sbom"},
		{ID: "signed", TenantID: "tenant", Kind: "sign_bundle", SubjectType: "release_bundle", SubjectID: "bundle", Payload: map[string]any{"manifest_hash": "sha256:fixture"}},
		{ID: "verified", TenantID: "tenant", Kind: "verify_subject", SubjectType: "evidence_item", SubjectID: "evidence", Payload: map[string]any{"result_id": "result"}},
	}
	for _, job := range jobs {
		if err := p.Process(ctx, job); err != nil {
			t.Fatal("native recorded metadata job failed", job.Kind, err)
		}
		foreign := job
		foreign.TenantID = "other"
		if err := p.Process(ctx, foreign); err == nil {
			t.Fatal("foreign worker subject accepted", job.Kind)
		}
	}
	if err := p.Process(ctx, postgres.ClaimedJob{Kind: "unknown"}); err == nil || classifyWorkerFailure(err).Class != postgres.JobFailurePoisoned {
		t.Fatal("unsupported native job accepted", err)
	}
	data := []byte("payload-data")
	digest := digestBytes(data)
	hex := strings.TrimPrefix(digest, "sha256:")
	now := time.Now().UTC().Truncate(time.Microsecond)
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
	if err := uow.Repositories().Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if err := uow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	job := postgres.ClaimedJob{ID: "finalize", TenantID: "tenant", Kind: "finalize_payload", Payload: map[string]any{"payload_digest": digest}}
	for range 2 {
		if err := p.Process(ctx, job); err != nil {
			t.Fatal("native finalize/replay failed", err)
		}
	}
	stored, err := store.GetObjectPayload(ctx, "tenant", digest)
	if err != nil || stored.Status != app.ObjectPayloadFinalized {
		t.Fatal("payload not durably finalized", stored, err)
	}
	got, err := objects.GetBounded(ctx, payload.FinalKey, int64(len(data)))
	if err != nil || !bytes.Equal(got.Bytes, data) {
		t.Fatal("finalized bytes changed", got, err)
	}
	if _, _, err := store.LoadState(ctx); err == nil {
		t.Fatal("native worker replaced aggregate canary")
	}
}
