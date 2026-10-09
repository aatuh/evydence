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

func TestRedactionNativeFixtureRequiresCurrentTenantAndAtomicDetachedPolicy(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("redaction used aggregate clock") }})
	f := packageFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopePackageWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{app.ScopePackageWrite}}}}
	in := packageapp.CreateRedactionProfileInput{Name: " Customer ", Description: " Review ", AllowedTypes: []string{"vex", "sbom", "sbom"}, ExcludedFields: []string{"internal_notes", "api_key", "api_key", " "}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateRedactionProfile(t.Context(), human, in); err != nil {
		t.Fatal("current tenant preflight", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("profile preflight mutated state", err)
	}
	v, err := f.CreateRedactionProfile(t.Context(), human, in)
	if err != nil {
		t.Fatal(err)
	}
	want := packagedomain.RedactionProfile{ID: v.ID, TenantID: human.TenantID, Name: "Customer", Description: "Review", AllowedTypes: []string{"sbom", "vex"}, ExcludedFields: []string{"api_key", "internal_notes"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: v.CreatedAt}
	if v.ID == "" || v.CreatedAt.IsZero() || !reflect.DeepEqual(v, want) {
		t.Fatal("profile lost full normalized DTO", v, want)
	}
	v.AllowedTypes[0], v.ExcludedFields[0] = "mutated", "mutated"
	after, err := base.Snapshot()
	if err != nil || len(after.RedactionProfiles) != len(before.RedactionProfiles)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(after.OutboxJobs) != len(before.OutboxJobs) || len(after.CustomerPackages) != len(before.CustomerPackages) {
		t.Fatal("profile/audit effects incomplete or unrelated writes", err)
	}
	if !reflect.DeepEqual(after.RedactionProfiles[want.ID], domain.RedactionProfile(want)) {
		t.Fatal("profile caller mutation reached storage")
	}
	a := after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID])]
	if a.EntryType != "redaction_profile.created" || a.SubjectID != want.ID || a.ActorID != human.UserID || a.ActorType != "human_user" || a.OccurredAt != want.CreatedAt {
		t.Fatal("profile audit lost identity/caller/time")
	}
	factory.fail = true
	if v, err := f.CreateRedactionProfile(t.Context(), human, in); err == nil || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("failed profile commit returned data", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed profile commit published row/audit", err)
	}
}

func TestRedactionNativeFixtureRejectsProductGrantsUnknownTenantsAndMissingRepositories(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	f := packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	in := packageapp.CreateRedactionProfileInput{Preset: "customer_safe"}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopePackageWrite}}
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}, {{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}}}} {
		human.ResourceGrants = grants
		if err := f.AuthorizeCreateRedactionProfile(t.Context(), human, in); !errors.Is(err, packageapp.ErrForbidden) {
			t.Fatal("non-tenant grant preflight", err)
		}
		if v, err := f.CreateRedactionProfile(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
			t.Fatal("non-tenant grant created profile", err)
		}
	}
	unknown := owner.actor
	unknown.TenantID = "unknown"
	if err := f.AuthorizeCreateRedactionProfile(t.Context(), unknown, in); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("preflight did not fence current tenant", err)
	}
	if v, err := f.CreateRedactionProfile(t.Context(), unknown, in); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("unknown tenant profile created", err)
	}
	missing := packageFixtureCommands{catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}}
	if err := missing.AuthorizeCreateRedactionProfile(t.Context(), owner.actor, in); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("missing profile repository preflight fell back", err)
	}
	if v, err := missing.CreateRedactionProfile(t.Context(), owner.actor, in); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("missing profile repository write fell back", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateRedactionProfile(ctx, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("profile cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied profile changed state", err)
	}
}
