package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestCommercialCollectorNativeFixtureUsesCurrentIdentityAndAtomicHumanAudit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	at := peripheralFixtureQueryClock()
	aggregateClockCalls, clockCalls := 0, 0
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { aggregateClockCalls++; return at.Add(time.Hour) }})
	aggregateClockCalls = 0
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: application.ClockFunc(func() time.Time { clockCalls++; return at })}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"collector:admin"}}}}
	in := integrationapp.CreateCommercialCollectorInput{Name: "Scanner", Provider: "provider", Version: "1", ManifestHash: "sha256:" + strings.Repeat("a", 64), AllowedScopes: []string{"evidence:write"}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateCommercialCollectorDefinition(t.Context(), human, in); err != nil || clockCalls != 0 || aggregateClockCalls != 0 {
		t.Fatal("commercial preflight used command or aggregate time", err)
	}
	v, err := f.CreateCommercialCollectorDefinition(t.Context(), human, in)
	if err != nil || v.ID == "" || v.TenantID != human.TenantID || v.Name != in.Name || v.Provider != in.Provider || v.Version != in.Version || v.ManifestHash != in.ManifestHash || v.Status != "available" || v.SchemaVersion != integrationdomain.CommercialCollectorVersion || !v.CreatedAt.Equal(at) || !reflect.DeepEqual(v.AllowedScopes, in.AllowedScopes) || clockCalls != 1 || aggregateClockCalls != 0 {
		t.Fatal("commercial creation lost complete fields or bypassed focused dependencies", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.CommercialCollectors) != len(before.CommercialCollectors)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || !reflect.DeepEqual(after.APIKeys, before.APIKeys) || !reflect.DeepEqual(after.Collectors, before.Collectors) {
		t.Fatal("commercial definition/audit were not atomic or issued collector credentials", err)
	}
	entry := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
	if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.EntryType != "commercial_collector.created" || entry.SubjectID != v.ID || entry.PayloadHash != in.ManifestHash {
		t.Fatal("commercial audit lost human principal or manifest binding")
	}
	v.AllowedScopes[0] = "modified"
	if v, err := f.CreateCommercialCollectorDefinition(t.Context(), human, in); !errors.Is(err, app.ErrConflict) || v.ID != "" || clockCalls != 1 {
		t.Fatal("current duplicate commercial identity used generation dependencies", err)
	}
	factory.fail = true
	in.Name = "Failed"
	if v, err := f.CreateCommercialCollectorDefinition(t.Context(), human, in); err == nil || !reflect.DeepEqual(v, integrationdomain.CommercialCollectorDefinition{}) {
		t.Fatal("failed commercial commit exposed partial metadata", err)
	}
	factory.fail = false
	human.ResourceGrants = nil
	if v, err := f.CreateCommercialCollectorDefinition(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) || v.ID != "" {
		t.Fatal("revoked tenant grant accepted commercial definition", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateCommercialCollectorDefinition(cancelled, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("commercial command ignored cancellation", err)
	}
	final, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, final) {
		t.Fatal("failed/denied commercial write or result mutation changed state", err)
	}
}

func TestCommercialCollectorNativeFixtureReadsCurrentPageAndDiscardsFailedCommit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	want := domain.CommercialCollectorDefinition{ID: "owned-definition", TenantID: owner.actor.TenantID, Name: "Scanner", Provider: "provider", Version: "1", ManifestHash: "sha256:" + strings.Repeat("a", 64), AllowedScopes: []string{"evidence:write"}, Status: "available", SchemaVersion: domain.CommercialCollectorVersion, CreatedAt: peripheralFixtureQueryClock()}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.Enterprise.InsertCommercialCollectorDefinition(ctx, want); err != nil {
			return err
		}
		v := want
		v.ID, v.TenantID = "foreign-definition", foreign.actor.TenantID
		return r.Enterprise.InsertCommercialCollectorDefinition(ctx, v)
	}); err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("commercial query used aggregate clock") }})
	f := commercialCollectorPageFixture{catalogFixtureCommands{ledger: rebound}}
	req := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.ListPage(t.Context(), owner.actor, req, nil)
	if err != nil || !reflect.DeepEqual(page.Items, []integrationdomain.CommercialCollectorDefinition{integrationdomain.CommercialCollectorDefinition(want)}) || page.Next != nil {
		t.Fatal("current commercial page lost complete public DTO or tenant scope", err)
	}
	page.Items[0].AllowedScopes[0] = "modified"
	factory.fail = true
	if page, err := f.ListPage(t.Context(), owner.actor, req, nil); err == nil || !reflect.DeepEqual(page, appquery.Result[integrationdomain.CommercialCollectorDefinition]{}) {
		t.Fatal("failed commercial read returned metadata", err)
	}
	factory.fail = false
	denied := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:read"}}
	if _, err := f.ListPage(t.Context(), denied, req, nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("commercial query accepted missing tenant grant", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("commercial read or detached scope mutation changed state", err)
	}
}

func TestCommercialCollectorNativeFixtureRejectsMissingRepositoriesAndUnknownTenant(t *testing.T) {
	in := integrationapp.CreateCommercialCollectorInput{Name: "Scanner", Provider: "provider", Version: "1", ManifestHash: "sha256:" + strings.Repeat("a", 64), AllowedScopes: []string{"evidence:write"}}
	a := domain.Actor{TenantID: "unknown", KeyID: "admin", Scopes: []string{"*"}}
	for _, factory := range []app.UnitOfWorkFactory{nil, app.NewMemoryUnitOfWorkFactory()} {
		ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory})
		f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
		if err := f.AuthorizeCreateCommercialCollectorDefinition(t.Context(), a, in); err == nil {
			t.Fatal("commercial preflight accepted missing repositories or tenant")
		}
		if v, err := f.CreateCommercialCollectorDefinition(t.Context(), a, in); err == nil || !reflect.DeepEqual(v, integrationdomain.CommercialCollectorDefinition{}) {
			t.Fatal("invalid commercial transaction exposed metadata", err)
		}
		reader := commercialCollectorPageFixture{catalogFixtureCommands{ledger: ledger}}
		req := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
		if v, err := reader.ListPage(t.Context(), a, req, nil); err == nil || !reflect.DeepEqual(v, appquery.Result[integrationdomain.CommercialCollectorDefinition]{}) {
			t.Fatal("invalid commercial read exposed a page", err)
		}
	}
}
