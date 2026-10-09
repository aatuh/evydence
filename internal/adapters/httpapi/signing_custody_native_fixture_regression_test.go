package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestSigningCustodyNativeFixtureReadsCurrentRecordsWithoutAggregateClock(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, r app.Repositories) error {
		for _, actor := range []domain.Actor{owner.actor, foreign.actor} {
			if err := r.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{ID: "provider-" + actor.TenantID, TenantID: actor.TenantID, Name: "HSM profile", Type: "native_pkcs11_hsm", Status: "active", KeyRef: "pkcs11:object=fixture", Encrypted: true, SchemaVersion: "1", CreatedAt: time.Now().UTC()}); err != nil {
				return err
			}
		}
		return r.Integrity.InsertObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicy{ID: "policy", TenantID: owner.actor.TenantID, Name: "Retention", ObjectPrefix: "tenants/" + owner.actor.TenantID + "/", Mode: "governance", RetentionDays: 7, MaxVerificationAgeHours: 24, Status: "configured", SchemaVersion: "1", CreatedAt: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("custody report consulted aggregate clock") }})
	query := custodyFixtureQuery{catalogFixtureCommands{ledger: rebound}}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	report, err := query.Report(t.Context(), owner.actor)
	if err != nil || report.TenantID != owner.actor.TenantID || len(report.SigningProviders) != 1 || report.SigningProviders[0].ID != "provider-"+owner.actor.TenantID || len(report.ObjectRetentionPolicies) != 1 || report.Checks[0].Result != "passed" || report.Checks[1].Result != "passed" || report.Checks[2].Result != "failed" || len(report.Limitations) == 0 || report.GeneratedAt.IsZero() {
		t.Fatal("native custody report lost current ownership, checks or limitations", err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("custody report modified repository state", err)
	}
	factory.fail = true
	report, err = query.Report(t.Context(), owner.actor)
	if err == nil || !reflect.DeepEqual(report, verificationdomain.SigningCustodyReviewReport{}) {
		t.Fatal("failed read commit exposed custody report", err)
	}
}

func TestSigningCustodyNativeFixtureRequiresRepositoryAndPreservesExplicitPort(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", Now: func() time.Time { panic("custody report used aggregate clock") }})
	query := custodyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"keys:admin"}}
	report, err := query.Report(t.Context(), actor)
	if !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(report, verificationdomain.SigningCustodyReviewReport{}) {
		t.Fatal("missing repository restored aggregate behavior or exposed a report", err)
	}
	actor.Scopes = nil
	if _, err := query.Report(t.Context(), actor); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("missing tenant-wide authority reached repository composition", err)
	}
	actor.Scopes = []string{"keys:admin"}
	var missingContext context.Context
	if _, err := query.Report(missingContext, actor); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil context was accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.Report(ctx, actor); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated", err)
	}
	explicit := &custodyQueryFake{}
	server := &Server{signingCustodyQuery: explicit}
	server.bindVerificationReadFixturePorts(ledger)
	if server.signingCustodyQuery != explicit {
		t.Fatal("fixture binding replaced an explicit focused custody query")
	}
}
