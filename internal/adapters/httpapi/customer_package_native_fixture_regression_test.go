package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestCustomerPackageNativeFixtureUsesCurrentRepositoriesAndAtomicDetachedManifest(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	profile, err := createRedactionProfileFixture(t.Context(), ledger, owner.actor, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("customer package used aggregate clock") }})
	f := packageFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopePackageWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopePackageWrite}}}}
	in := packageapp.CreateCustomerPackageInput{ProductID: owner.product.ID, RedactionProfileID: profile.ID, Title: "Review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateCustomerSecurityPackage(t.Context(), human, in); err != nil {
		t.Fatal("current scope/policy preflight", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("customer preflight wrote state", err)
	}
	v, err := f.CreateCustomerSecurityPackage(t.Context(), human, in)
	if err != nil {
		t.Fatal("focused creation could not see current profile/scope", err)
	}
	if v.ID == "" || v.ManifestHash == "" || v.ProductID != owner.product.ID || v.RedactionProfileID != profile.ID || v.State != "generated" || v.CreatedAt.IsZero() {
		t.Fatal("customer creation lost full result", v)
	}
	v.Manifest["mutated"] = "changed"
	after, err := base.Snapshot()
	if err != nil || len(after.CustomerPackages) != len(before.CustomerPackages)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(after.Signatures) != len(before.Signatures) || len(after.OutboxJobs) != len(before.OutboxJobs) {
		t.Fatal("customer effects incomplete or unrelated writes", err)
	}
	if _, exists := after.CustomerPackages[v.ID].Manifest["mutated"]; exists {
		t.Fatal("caller mutation reached package storage")
	}
	a := after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID])]
	if a.SubjectID != v.ID || a.ActorID != human.UserID || a.ActorType != "human_user" || a.OccurredAt != v.CreatedAt {
		t.Fatal("customer audit lost caller/time")
	}
	factory.fail = true
	if got, err := f.CreateCustomerSecurityPackage(t.Context(), human, in); err == nil || !reflect.DeepEqual(got, packagedomain.CustomerSecurityPackage{}) {
		t.Fatal("failed customer commit returned package", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed customer commit published effects", err)
	}
}

func TestCustomerPackageNativeFixtureRechecksCurrentScopeAndPolicyForPreflight(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	other := seedEvidenceFixtureScope(t, ledger, "Other")
	p, err := createRedactionProfileFixture(t.Context(), ledger, owner.actor, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	f := packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	in := packageapp.CreateCustomerPackageInput{ProductID: owner.product.ID, RedactionProfileID: p.ID, Title: "Review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*packageapp.CreateCustomerPackageInput){func(in *packageapp.CreateCustomerPackageInput) { in.ProductID = other.product.ID }, func(in *packageapp.CreateCustomerPackageInput) { in.RedactionProfileID = "missing" }, func(in *packageapp.CreateCustomerPackageInput) { in.ReleaseID = "missing" }} {
		bad := in
		change(&bad)
		if err := f.AuthorizeCreateCustomerSecurityPackage(t.Context(), owner.actor, bad); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatal("preflight skipped current parent/policy read", err)
		}
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopePackageWrite}}
	if err := f.AuthorizeCreateCustomerSecurityPackage(t.Context(), human, in); !errors.Is(err, packageapp.ErrForbidden) {
		t.Fatal("missing grant accepted", err)
	}
	missing := packageFixtureCommands{catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture"})}}
	if err := missing.AuthorizeCreateCustomerSecurityPackage(t.Context(), owner.actor, in); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("missing repositories fell back", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateCustomerSecurityPackage(ctx, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("customer cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied customer request mutated state", err)
	}
}
