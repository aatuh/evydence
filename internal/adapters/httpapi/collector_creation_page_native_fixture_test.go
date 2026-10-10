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
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorCountingCredentials struct {
	credentials *identityapp.HMACAuthenticationCredentials
	calls       int
	lastSecret  string
}

func (c *collectorCountingCredentials) GenerateCollectorCredential(ctx context.Context) (integrationapp.CollectorCredential, error) {
	if err := ctx.Err(); err != nil {
		return integrationapp.CollectorCredential{}, err
	}
	c.calls++
	v, err := c.credentials.Generate()
	c.lastSecret = v.Secret
	return integrationapp.CollectorCredential{Secret: v.Secret, Prefix: v.Prefix, Hash: v.Hash}, err
}

func TestCollectorCreationNativeFixtureUsesExplicitCredentialsClockAndAtomicWrites(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	clock := &ssoFixtureRebindClock{at: peripheralFixtureQueryClock()}
	clockReads := 0
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "unrelated", UnitOfWork: factory, Now: func() time.Time { clockReads++; return clock.at.Add(time.Hour) }})
	clockReads = 0
	credentials := &collectorCountingCredentials{credentials: fixtureSessionCredentials("issued-pepper")}
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, credentials: credentials, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"collector:admin"}}}}
	in := integrationapp.CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1", Scopes: []string{"evidence:write", "bundle:write"}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateCollector(t.Context(), human, in); err != nil || credentials.calls != 0 || clockReads != 0 {
		t.Fatal("creation preflight issued credentials or used aggregate time", err)
	}
	v, key, secret, err := f.CreateCollector(t.Context(), human, in)
	if err != nil || v.ID == "" || key.ID != v.APIKeyID || secret == "" || key.Hash != "" || !key.CreatedAt.Equal(clock.at) || !v.CreatedAt.Equal(clock.at) || credentials.calls != 1 || clockReads != 0 {
		t.Fatal("collector creation bypassed explicit credentials/time or lost public fields", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.Collectors) != len(before.Collectors)+1 || len(after.APIKeys) != len(before.APIKeys)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || after.APIKeys[key.ID].Hash != credentials.credentials.Hash(secret) {
		t.Fatal("collector, credential and audit did not commit together", err)
	}
	entry := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
	if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.SubjectID != v.ID || entry.EntryType != "collector.created" {
		t.Fatal("collector creation audit lost human principal")
	}
	createdCollectorID, createdKeyID := v.ID, key.ID
	v.AllowedScopes[0], key.Scopes[0] = "modified", "modified"
	factory.fail = true
	in.Name = "Failure"
	v, key, failedSecret, err := f.CreateCollector(t.Context(), human, in)
	if err == nil || !reflect.DeepEqual(v, integrationdomain.Collector{}) || key.ID != "" || failedSecret != "" {
		t.Fatal("failed collector commit exposed credentials or resource", err)
	}
	factory.fail = false
	if _, err := fixtureIdentityAuthenticator(rebound, "issued-pepper", clock).Authenticate(t.Context(), credentials.lastSecret); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("rolled-back collector credential authenticated", err)
	}
	calls := credentials.calls
	in.Name = "Builder"
	if _, _, secret, err := f.CreateCollector(t.Context(), human, in); !errors.Is(err, app.ErrConflict) || secret != "" || credentials.calls != calls {
		t.Fatal("duplicate collector minted a credential", err)
	}
	human.ResourceGrants = nil
	in.Name = "Denied"
	if _, _, secret, err := f.CreateCollector(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) || secret != "" || credentials.calls != calls {
		t.Fatal("revoked creation grant minted a credential", err)
	}
	final, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, final) {
		t.Fatal("failed/denied creation or detached metadata changed repository state", err)
	}
	actor, err := fixtureIdentityAuthenticator(rebound, "issued-pepper", clock).Authenticate(t.Context(), secret)
	if err != nil || actor.TenantID != human.TenantID || actor.CollectorID != createdCollectorID || actor.KeyID != createdKeyID || !reflect.DeepEqual(actor.Scopes, []string{"bundle:write", "evidence:write"}) {
		t.Fatal("committed native collector lost least-privilege authentication binding", err)
	}
}

func TestCollectorPageNativeFixtureReadsCurrentStateAndDiscardsFailedCommit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("collector page used aggregate clock") }})
	f := collectorPageFixture{catalogFixtureCommands{ledger: rebound}}
	req := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.ListPage(t.Context(), owner.actor, req, nil)
	want, conversionErr := fixtureCollector(owner.collector)
	if err != nil || conversionErr != nil || !reflect.DeepEqual(page.Items, []integrationdomain.Collector{want}) || page.Next != nil {
		t.Fatal("current collector page lost complete public DTO", err, conversionErr)
	}
	encoded, err := json.Marshal(page.Items)
	if err != nil || strings.Contains(string(encoded), `"hash"`) || strings.Contains(string(encoded), foreign.collector.ID) {
		t.Fatal("collector inventory exposed credentials or another tenant", err)
	}
	page.Items[0].AllowedScopes[0] = "modified"
	factory.fail = true
	page, err = f.ListPage(t.Context(), owner.actor, req, nil)
	if err == nil || !reflect.DeepEqual(page, appquery.Result[integrationdomain.Collector]{}) {
		t.Fatal("failed read commit returned collector metadata", err)
	}
	factory.fail = false
	denied := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:read"}}
	if _, err := f.ListPage(t.Context(), denied, req, nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("collector page accepted absent tenant grant", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("collector read or detached scopes changed state", err)
	}
}

func TestCollectorCreationNativeFixturePreservesBoundResourcesAndFailsWithoutRepositories(t *testing.T) {
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	clock := &ssoFixtureRebindClock{at: peripheralFixtureQueryClock()}
	server.bindCollectorFixtureResources("fixture-pepper", clock)
	old := server.collectorCommands.(integrationFixtureCommands)
	oldAuth := server.authn.(identityNativeFixtureAuthenticator)
	second := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	server.bindLegacyLedgerFixture(second)
	current := server.collectorCommands.(integrationFixtureCommands)
	auth := server.authn.(identityNativeFixtureAuthenticator)
	if current.ledger != second || current.clock != clock || current.credentials != old.credentials || auth.ledger != second || auth.clock != clock || auth.credentials != oldAuth.credentials {
		t.Fatal("collector rebinding lost explicit credentials, clock or authentication")
	}
	customAuth := &configuredAuthenticator{actor: domain.Actor{TenantID: "explicit", KeyID: "explicit"}}
	customCommands := &collectorHTTPFake{}
	server.authn, server.collectorCommands = customAuth, customCommands
	server.bindCollectorFixtureResources("fixture-pepper", clock)
	server.bindIntegrationFixtureCommands(second)
	if server.authn != customAuth || server.collectorCommands != customCommands {
		t.Fatal("collector binding replaced explicit ports")
	}
	missing := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper"})
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: missing}}
	a := domain.Actor{TenantID: "tenant", KeyID: "admin", Scopes: []string{"*"}}
	in := integrationapp.CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1"}
	if v, key, secret, err := f.CreateCollector(t.Context(), a, in); err == nil || !reflect.DeepEqual(v, integrationdomain.Collector{}) || key.ID != "" || secret != "" {
		t.Fatal("missing repositories returned a collector or credential", err)
	}
	if err := f.AuthorizeCreateCollector(t.Context(), a, in); err == nil {
		t.Fatal("missing repositories accepted collector preflight")
	}
}
