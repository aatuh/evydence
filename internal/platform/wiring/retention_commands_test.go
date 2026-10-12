package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type retentionProviderFake struct {
	result  app.ObjectRetentionResult
	err     error
	calls   int
	hook    func()
	request app.ObjectRetentionRequest
}

func (f *retentionProviderFake) VerifyObjectRetention(_ context.Context, request app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	f.calls++
	f.request = request
	if f.hook != nil {
		f.hook()
	}
	return f.result, f.err
}

func TestPostgresRetentionCommandsPersistCurrentReceiptsAndRejectSameStatusRaces(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('foreign','Foreign')`)
	hold := true
	provider := &retentionProviderFake{result: app.ObjectRetentionResult{Provider: "s3", Bucket: "bucket", ObjectKey: "tenants/tenant/raw/sample", Mode: "compliance", RetentionDays: 90, Enforced: true, LegalHold: &hold, ObservedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), Checks: []domain.VerifyCheck{{Name: "provider_lock", Result: "passed"}}}}
	commands, err := BuildRetentionCommands(store, store, provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"admin", "verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin", "verify:read"}}}}
	policy, err := commands.CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "lock", Mode: "compliance", RetentionDays: 30, ObjectKey: "tenants/tenant/raw/sample", RequireLegalHold: true})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil || verified.Status != "verified" || verified.VerificationHash == "" || verified.VerificationExpiresAt == nil || provider.calls != 1 || provider.request.TenantID != "tenant" || !provider.request.RequireLegalHold {
		t.Fatalf("durable verified=%#v err=%v", verified, err)
	}
	// A later verifier commits while this request is fetching provider facts.
	// The status stays verified: the full snapshot, not status alone, must CAS.
	provider.hook = func() {
		exec(`UPDATE object_retention_policies SET verification_hash='newer-receipt' WHERE id=$1`, policy.ID)
	}
	if _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("same-status race accepted", err)
	}
	var hash string
	var audits int
	if err := pool.QueryRow(ctx, `SELECT verification_hash FROM object_retention_policies WHERE id=$1`, policy.ID).Scan(&hash); err != nil || hash != "newer-receipt" {
		t.Fatal("newer receipt overwritten", hash, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries`).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("conflict wrote audit", audits, err)
	}
	provider.hook = nil
	beforeMalformed := provider.calls
	exec(`UPDATE object_retention_policies SET verification_checks='{}' WHERE id=$1`, policy.ID)
	if _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); !errors.Is(err, verificationapp.ErrConflict) || provider.calls != beforeMalformed {
		t.Fatal("malformed checks reached provider", err)
	}
	exec(`UPDATE object_retention_policies SET verification_checks='[]' WHERE id=$1`, policy.ID)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := commands.VerifyObjectRetentionPolicy(cancelled, actor, policy.ID); !errors.Is(err, context.Canceled) || provider.calls != beforeMalformed {
		t.Fatal("cancelled verification reached provider", err)
	}
	exec(`UPDATE object_retention_policies SET verification_limitations=ARRAY[repeat('x',9*1024*1024)] WHERE id=$1`, policy.ID)
	before := provider.calls
	actor.ResourceGrants[0].ResourceID = "foreign"
	if _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); !errors.Is(err, application.ErrForbidden) || provider.calls != before {
		t.Fatal("grant denial read metadata or called provider", err)
	}
	actor.ResourceGrants[0].ResourceID = "tenant"
	if _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); !errors.Is(err, verificationapp.ErrConflict) || provider.calls != before {
		t.Fatal("oversized policy called provider", err)
	}
	actor.TenantID = "foreign"
	actor.ResourceGrants[0].ResourceID = "foreign"
	if _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); !errors.Is(err, verificationapp.ErrNotFound) || provider.calls != before {
		t.Fatal("foreign policy exposed", err)
	}
	actor.TenantID = "tenant"
	actor.ResourceGrants[0].ResourceID = "tenant"
	exec(`UPDATE object_retention_policies SET verification_limitations='{}' WHERE id=$1`, policy.ID)
	// Provider unavailability records a conservative receipt, never its error.
	provider.err = errors.New("provider password=private-secret")
	got, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil || got.Status != "not_verified" || got.VerificationProvider != "" {
		t.Fatal("unavailability", got, err)
	}
	for _, check := range got.VerificationChecks {
		if strings.Contains(check.Detail, "private-secret") {
			t.Fatal("provider detail leaked")
		}
	}
	provider.err = nil
	// Force the audit append to fail after the attempted receipt update.
	exec(`CREATE FUNCTION reject_retention_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''forced audit failure''; END'; CREATE TRIGGER reject_retention_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_retention_audit()`)
	if _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); err == nil {
		t.Fatal("audit failure hidden")
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM object_retention_policies WHERE id=$1`, policy.ID).Scan(&status); err != nil || status != "not_verified" {
		t.Fatal("failed audit published verification", status, err)
	}
	if _, err := commands.CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "rollback", Mode: "governance", RetentionDays: 30}); err == nil {
		t.Fatal("create audit failure hidden")
	}
	var policies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM object_retention_policies`).Scan(&policies); err != nil || policies != 1 {
		t.Fatal("failed creation published policy", policies, err)
	}
}

type barrierRetentionProvider struct {
	entered chan struct{}
	release chan struct{}
}

func (p barrierRetentionProvider) VerifyObjectRetention(ctx context.Context, _ app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	select {
	case p.entered <- struct{}{}:
	case <-ctx.Done():
		return app.ObjectRetentionResult{}, ctx.Err()
	}
	select {
	case <-p.release:
		return app.ObjectRetentionResult{}, nil
	case <-ctx.Done():
		return app.ObjectRetentionResult{}, ctx.Err()
	}
}
func TestPostgresRetentionCommandsSerializeCompetingObservations(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Tenant')`); err != nil {
		t.Fatal(err)
	}
	provider := barrierRetentionProvider{make(chan struct{}, 2), make(chan struct{})}
	commands, err := BuildRetentionCommands(store, store, provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin", "verify:read"}}
	policy, err := commands.CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "lock", Mode: "governance", RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID); results <- err }()
	}
	for range 2 {
		select {
		case <-provider.entered:
		case <-ctx.Done():
			t.Fatal("verifiers did not reach provider", ctx.Err())
		}
	}
	close(provider.release)
	success, conflicts := 0, 0
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				success++
			} else if errors.Is(err, verificationapp.ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("competing receipts both committed", success, conflicts)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries`).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("conflict appended audit", audits, err)
	}
}

func TestPostgresRetentionCommandsWithoutProviderRemainLocalIntent(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Tenant')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildRetentionCommands(store, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin", "verify:read"}}
	policy, err := commands.CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "lock", Mode: "governance", RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	got, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil || got.Status != "not_verified" || got.VerificationHash == "" || got.VerificationProvider != "" || got.VerificationObservedAt != nil || got.VerificationExpiresAt != nil {
		t.Fatal("local intent became provider proof", got, err)
	}
}

func TestPostgresRetentionCommandsPreserveIdempotentCreationAndVerification(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Tenant')`); err != nil {
		t.Fatal(err)
	}
	provider := &retentionProviderFake{}
	commands, err := BuildRetentionCommands(store, store, provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin", "verify:read"}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	var policyID string
	for range 2 {
		_, response, err := executor.WithBody(ctx, actor, "POST", "/v1/object-retention-policies", "create", []byte(`{"name":"lock"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			policy, err := commands.CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "lock", Mode: "governance", RetentionDays: 30})
			policyID = policy.ID
			return 201, domain.ObjectRetentionPolicyFromContextModel(policy), err
		})
		if err != nil || response == nil {
			t.Fatal("creation replay", err)
		}
	}
	for range 2 {
		_, _, err := executor.WithBody(ctx, actor, "POST", "/v1/object-retention-policies/"+policyID+"/verify", "verify", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			policy, err := commands.VerifyObjectRetentionPolicy(ctx, actor, policyID)
			return 200, domain.ObjectRetentionPolicyFromContextModel(policy), err
		})
		if err != nil {
			t.Fatal("verification replay", err)
		}
	}
	if provider.calls != 1 {
		t.Fatal("replay called provider", provider.calls)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM object_retention_policies`).Scan(&count); err != nil || count != 1 {
		t.Fatal("replay duplicated policy", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries`).Scan(&count); err != nil || count != 2 {
		t.Fatal("replay duplicated audit", count, err)
	}
}
