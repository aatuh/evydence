package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestCustomerAccessNativeFixtureUsesCurrentPackageWithoutAggregateClockAndCommitsOnlyCountAudit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	profile, err := createRedactionProfileFixture(t.Context(), ledger, owner.actor, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := createCustomerPackageFixture(t.Context(), ledger, owner.actor, packageapp.CreateCustomerPackageInput{ProductID: owner.product.ID, RedactionProfileID: profile.ID, Title: "Review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("access used aggregate clock") }})
	f := customerAccessFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopePackageRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: pkg.ID, Scopes: []string{app.ScopePackageRead}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.AccessCustomerSecurityPackage(t.Context(), human, pkg.ID)
	if err != nil || v.ID != pkg.ID || v.AccessCount != 1 {
		t.Fatal("access did not read current stored package", v, err)
	}
	v.Manifest["mutated"] = "changed"
	report, err := f.SecurityReviewPackageReport(t.Context(), human, pkg.ID)
	if err != nil || report.PackageID != pkg.ID || report.ProductID != pkg.ProductID || report.ReportType != "security_review_package" || len(report.Assumptions) == 0 || len(report.Limitations) == 0 {
		t.Fatal("frozen report result lost fields", report, err)
	}
	after, err := base.Snapshot()
	if err != nil || after.CustomerPackages[pkg.ID].AccessCount != 2 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+2 || len(after.OutboxJobs) != len(before.OutboxJobs) || len(after.Signatures) != len(before.Signatures) {
		t.Fatal("access/report count-audit effects changed", err)
	}
	if !reflect.DeepEqual(after.CustomerPackages[pkg.ID].Manifest, before.CustomerPackages[pkg.ID].Manifest) || after.CustomerPackages[pkg.ID].ManifestHash != pkg.ManifestHash {
		t.Fatal("access rewrote frozen package")
	}
	a := after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID])]
	if a.EntryType != "customer_package.accessed" || a.SubjectID != pkg.ID || a.ActorType != "human_user" || a.ActorID != human.UserID {
		t.Fatal("access audit lost identity or subject")
	}
	factory.fail = true
	if v, err := f.AccessCustomerSecurityPackage(t.Context(), human, pkg.ID); err == nil || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) {
		t.Fatal("failed access commit returned data", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed access committed counter/audit", err)
	}
}

func TestCustomerAccessNativeFixtureRejectsRevokedGrantsForeignScopeMissingRepositoriesAndCancellation(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	profile, err := createRedactionProfileFixture(t.Context(), ledger, owner.actor, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := createCustomerPackageFixture(t.Context(), ledger, owner.actor, packageapp.CreateCustomerPackageInput{ProductID: owner.product.ID, RedactionProfileID: profile.ID, Title: "Review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	f := customerAccessFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopePackageRead}}
	if v, err := f.AccessCustomerSecurityPackage(t.Context(), human, pkg.ID); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) {
		t.Fatal("revoked/missing grant accessed package", err)
	}
	if v, err := f.AccessCustomerSecurityPackage(t.Context(), foreign.actor, pkg.ID); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) {
		t.Fatal("foreign package returned", err)
	}
	missing := customerAccessFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}}
	if v, err := missing.AccessCustomerSecurityPackage(t.Context(), owner.actor, pkg.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) {
		t.Fatal("missing repositories fell back", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.AccessCustomerSecurityPackage(ctx, owner.actor, pkg.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("access cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied access changed state", err)
	}
}

func TestCustomerAccessNativeFixtureExpiryAndMalformedFrozenReportLeaveNoEffects(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	profile, err := createRedactionProfileFixture(t.Context(), ledger, owner.actor, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := createCustomerPackageFixture(t.Context(), ledger, owner.actor, packageapp.CreateCustomerPackageInput{ProductID: owner.product.ID, RedactionProfileID: profile.ID, Title: "Review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	malformed := pkg
	malformed.ID = "invalid-frozen-report"
	malformed.Manifest = map[string]any{"evidence_ids": []string{"duplicate", "duplicate"}}
	if err := app.ExecuteUnitOfWork(t.Context(), base, func(ctx context.Context, r app.Repositories) error {
		return r.Packages.InsertCustomerSecurityPackage(ctx, malformed)
	}); err != nil {
		t.Fatal(err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	f := customerAccessFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return pkg.ExpiresAt })}
	if v, err := f.AccessCustomerSecurityPackage(t.Context(), owner.actor, pkg.ID); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) {
		t.Fatal("package at expiry returned data", err)
	}
	f.clock = application.ClockFunc(func() time.Time { return pkg.CreatedAt })
	if report, err := f.SecurityReviewPackageReport(t.Context(), owner.actor, malformed.ID); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(report, packagedomain.SecurityReviewPackageReport{}) {
		t.Fatal("malformed frozen report returned data", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("expired access or malformed report committed effects", err)
	}
}

func TestCustomerAccessNativeFixtureBindingPreservesExplicitClockAndInjectedPorts(t *testing.T) {
	first := newLegacyLedgerFixture(app.Config{APIKeyPepper: "first-fixture"})
	second := newLegacyLedgerFixture(app.Config{APIKeyPepper: "second-fixture"})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	server := &Server{customerPackageAccessCommands: customerAccessFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: first}, clock: application.ClockFunc(func() time.Time { return now })}}
	server.bindPackageFixturePorts(second)
	f, ok := server.customerPackageAccessCommands.(customerAccessFixtureCommands)
	if !ok || f.ledger != second || f.clock == nil || !f.clock.Now().Equal(now) {
		t.Fatal("access binding lost explicit fixture dependencies")
	}
	injected := &customerPackageAccessHTTPFake{}
	server.customerPackageAccessCommands = injected
	server.bindPackageFixturePorts(first)
	if server.customerPackageAccessCommands != injected {
		t.Fatal("fixture binding replaced injected access service")
	}
}
