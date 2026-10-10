package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type retentionFixtureProviderFunc func(context.Context, app.ObjectRetentionRequest) (app.ObjectRetentionResult, error)

func (f retentionFixtureProviderFunc) VerifyObjectRetention(ctx context.Context, r app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	return f(ctx, r)
}

func TestRetentionNativeFixtureRechecksCurrentReceiptsAndDoesNotLeakProviderFailures(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	at, hold, calls := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC), true, 0
	key := "tenants/" + owner.actor.TenantID + "/raw/sample"
	observed := app.ObjectRetentionResult{Provider: "s3", Bucket: "fixture-bucket", ObjectKey: key, Mode: "compliance", RetentionDays: 90, Enforced: true, LegalHold: &hold, ObservedAt: at, Checks: []domain.VerifyCheck{{Name: "provider_lock", Result: "passed"}}, Limitations: []string{"sample only"}}
	provider := retentionFixtureProviderFunc(func(ctx context.Context, r app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
		calls++
		if r.TenantID != owner.actor.TenantID || r.ObjectKey != key || r.Mode != "compliance" || r.RetentionDays != 30 || !r.RequireLegalHold || ctx.Err() != nil {
			t.Fatal("provider received wrong policy coordinates")
		}
		return observed, nil
	})
	f := retentionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return at }), verifier: provider}
	input := verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "compliance", RetentionDays: 30, ObjectKey: key, RequireLegalHold: true}
	p, err := f.CreateObjectRetentionPolicy(t.Context(), owner.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	guard := f
	guard.clock = application.ClockFunc(func() time.Time { panic("retention guard allocated time") })
	guard.verifier = retentionFixtureProviderFunc(func(context.Context, app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
		panic("retention guard contacted provider")
	})
	if err := guard.AuthorizeCreateObjectRetentionPolicy(t.Context(), owner.actor, input); err != nil {
		t.Fatal(err)
	}
	if err := guard.AuthorizeVerifyObjectRetentionPolicy(t.Context(), owner.actor, p.ID); err != nil {
		t.Fatal(err)
	}
	if v, err := f.VerifyObjectRetentionPolicy(t.Context(), foreign.actor, p.ID); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("foreign retention verification returned facts", err)
	}
	denied := owner.actor
	denied.KeyID, denied.UserID, denied.ResourceGrants = "", "human", nil
	if v, err := f.VerifyObjectRetentionPolicy(t.Context(), denied, p.ID); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("removed tenant grant retained verification authority", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := f.VerifyObjectRetentionPolicy(ctx, owner.actor, p.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("cancelled retention verification returned facts", err)
	}
	guarded, err := factory.Snapshot()
	if err != nil || calls != 0 || !reflect.DeepEqual(before, guarded) {
		t.Fatal("retention guard or rejected call allocated provider/audit effects", err)
	}
	p, err = f.VerifyObjectRetentionPolicy(t.Context(), owner.actor, p.ID)
	if err != nil || p.Status != "verified" || calls != 1 || p.VerificationHash == "" || p.VerificationExpiresAt == nil || !p.VerificationExpiresAt.Equal(at.Add(24*time.Hour)) || p.VerificationLegalHold == nil || !*p.VerificationLegalHold {
		t.Fatal("injected observation lost receipt/freshness contract", err)
	}
	expected := domain.ObjectRetentionPolicyFromContextModel(p)
	observed.Checks[0].Detail, observed.Limitations[0], hold = "caller", "caller", false
	snapshot, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(snapshot.ObjectRetentionPolicies[p.ID], expected) {
		t.Fatal("provider observation aliases stored receipt", err)
	}
	var newer app.MemoryUnitOfWorkSnapshot
	f.verifier = retentionFixtureProviderFunc(func(ctx context.Context, _ app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
		tx, err := factory.BeginUnitOfWork(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		r := tx.Repositories().Integrity.(retentionFixtureReader)
		current, err := r.GetObjectRetentionPolicyForUpdate(ctx, owner.actor.TenantID, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		current.VerificationHash = "newer-receipt"
		if err := tx.Repositories().Integrity.UpdateObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicyFromContextModel(current), current.Status); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		newer, err = factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		return observed, nil
	})
	if v, err := f.VerifyObjectRetentionPolicy(t.Context(), owner.actor, p.ID); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("newer same-status receipt was overwritten", err)
	}
	afterConflict, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(newer, afterConflict) {
		t.Fatal("same-status conflict changed current policy or audit", err)
	}
	f.verifier = retentionFixtureProviderFunc(func(context.Context, app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
		return app.ObjectRetentionResult{}, errors.New("provider password=private-marker")
	})
	value, err := f.VerifyObjectRetentionPolicy(t.Context(), owner.actor, p.ID)
	if err != nil || value.Status != "not_verified" || value.VerificationProvider != "" || value.VerificationObservedAt != nil || value.VerificationExpiresAt != nil {
		t.Fatal("provider failure became observed retention proof", err)
	}
	raw, err := json.Marshal(value)
	if err != nil || strings.Contains(string(raw), "private-marker") || strings.Contains(string(raw), "password") {
		t.Fatal("retention receipt leaked raw provider failure", err)
	}
}

func TestRetentionNativeFixtureUsesCurrentPolicyWithoutAggregateClockOrProviderProof(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("retention used aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	p, err := f.CreateObjectRetentionPolicy(t.Context(), owner.actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30})
	if err != nil || p.ID == "" || p.TenantID != owner.actor.TenantID || p.Status != "configured" {
		t.Fatal("retention creation lost current tenant or intent", err)
	}
	p, err = f.VerifyObjectRetentionPolicy(t.Context(), owner.actor, p.ID)
	if err != nil || p.Status != "not_verified" || p.VerificationHash == "" || p.VerifiedAt == nil || p.VerificationProvider != "" || p.VerificationObservedAt != nil || len(p.VerificationChecks) == 0 || len(p.VerificationLimitations) == 0 {
		t.Fatal("unconfigured provider became verification proof or lost receipt", err)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.ObjectRetentionPolicies) != len(before.ObjectRetentionPolicies)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 || !reflect.DeepEqual(after.OutboxJobs, before.OutboxJobs) || !reflect.DeepEqual(after.SigningKeys, before.SigningKeys) {
		t.Fatal("retention effects escaped owned policy/audit paths", err)
	}
}

func TestRetentionNativeFixtureCommitFailureLeavesNoPolicyOrObservation(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	factory := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	p, err := f.CreateObjectRetentionPolicy(t.Context(), owner.actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.failAt = factory.begins + 1
	if v, err := f.CreateObjectRetentionPolicy(t.Context(), owner.actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "Rollback", Mode: "governance", RetentionDays: 30}); err == nil || !reflect.DeepEqual(v, verificationdomain.ObjectRetentionPolicy{}) || factory.begins != factory.failAt {
		t.Fatal("creation commit failure not exercised or returned policy", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed retention create left policy or audit", err)
	}
	// The standalone focused read completes first, then the receipt write.
	factory.failAt = factory.begins + 2
	if v, err := f.VerifyObjectRetentionPolicy(t.Context(), owner.actor, p.ID); err == nil || !reflect.DeepEqual(v, verificationdomain.ObjectRetentionPolicy{}) || factory.begins != factory.failAt {
		t.Fatal("verification commit failure not exercised or returned policy", err)
	}
	after, err = base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed retention verification left observation or audit", err)
	}
}
