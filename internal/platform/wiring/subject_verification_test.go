package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresSubjectVerificationCompositionSharesReplayAndRollbackTransaction(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Subject dispatch'),('other','Other')`)
	exec(`INSERT INTO backup_manifests(id,tenant_id,state_hash,resource_counts,consistency_checks,limitations,schema_version,created_at)VALUES('backup','tenant','sha256:backup','{}','[{"name":"recorded","result":"passed"}]','{}','backup-manifest.v1.0.0',now()),('foreign','other','sha256:foreign','{}','[]','{}','backup-manifest.v1.0.0',now())`)
	checks := []app.ReadinessCheck{
		{Name: "postgres", Check: func(context.Context) error { return nil }},
		{Name: "migrations", Check: func(context.Context) error { return nil }},
		{Name: "writer_lease", Check: func(context.Context) error { return nil }},
		{Name: "signing_config", Check: func(context.Context) error { return nil }},
	}
	objects, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects, Production: true}, "test-only-pepper", checks)
	if err != nil {
		t.Fatal(err)
	}
	command := options.SubjectVerification
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
	want := 0
	counts := func() {
		t.Helper()
		var receipts, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&receipts, &audits, &jobs); err != nil || receipts != want || audits != want || jobs != want {
			t.Fatal(receipts, audits, jobs, want, err)
		}
	}
	for _, request := range []struct {
		kind, id string
		actor    identitydomain.Actor
		want     error
	}{
		{"unknown", "subject", actor, verificationapp.ErrValidation},
		{"backup_manifest", "foreign", actor, verificationapp.ErrNotFound},
		{"backup_manifest", "backup", identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, verificationapp.ErrForbidden},
		{"backup_manifest", "backup", identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}}, verificationapp.ErrForbidden},
	} {
		if r, err := command.VerifySubject(ctx, request.actor, request.kind, request.id); !errors.Is(err, request.want) || r.ID != "" {
			t.Fatal(request, r, err)
		}
		counts()
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	var first any
	for range 2 {
		status, body, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "composed-replay", []byte(`{"subject_type":"backup_manifest","subject_id":"backup"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := command.VerifySubject(ctx, actor, "backup_manifest", "backup")
			if r.Result.String() != "passed" || r.Profile.PayloadDigest != "sha256:backup" {
				t.Fatal(r, err)
			}
			return 200, verificationResultToLegacy(r), err
		})
		if err != nil || status != 200 || body == nil {
			t.Fatal(status, body, err)
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		var normalized any
		if err := json.Unmarshal(encoded, &normalized); err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = normalized
		} else if !reflect.DeepEqual(normalized, first) {
			t.Fatal("changed replay response", normalized, first)
		}
	}
	if calls != 1 {
		t.Fatal("duplicate composed receipt", calls)
	}
	want++
	counts()
	exec(`UPDATE backup_manifests SET consistency_checks='[{"name":"recorded","result":"failed"}]' WHERE id='backup'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "composed-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := command.VerifySubject(ctx, actor, "backup_manifest", "backup")
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts()
	var failedState string
	var failedResponse []byte
	if err := pool.QueryRow(ctx, `SELECT state,response FROM idempotency_records WHERE tenant_id='tenant' AND idempotency_key='composed-failed'`).Scan(&failedState, &failedResponse); err != nil || failedState != "failed" || string(failedResponse) != "null" {
		t.Fatal("failed command retained a receipt replay", failedState, string(failedResponse), err)
	}
	if r, err := command.VerifySubject(ctx, actor, "backup_manifest", "backup"); !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
		t.Fatal(r, err)
	}
	want++
	counts()
}
