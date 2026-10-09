package httpapi

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestSecurityUpdateNativeFixtureKeepsFailedCommitPrivateAndRequiresRepositories(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedPackageReportFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt}
	server.bindPackageReportFixtureClock(clock.Now)
	factory.fail = true
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rollbacks, begins := factory.rollbacks, factory.beginCalls
	body := getRaw(t, server, "fixture", "/v1/reports/security-update-evidence?product_id="+owner.product.ID+"&release_id="+owner.release.ID, http.StatusInternalServerError).Body.String()
	if factory.rollbacks != rollbacks+1 || factory.beginCalls != begins+1 || clock.calls != 0 {
		t.Fatal("failed security-update read retained a transaction or consulted the clock")
	}
	for _, private := range []string{"private-query-commit-secret", "private-triage", "fixed_decisions", "remediation_tasks", `"data"`} {
		if strings.Contains(body, private) {
			t.Fatal("failed report disclosed private error or partial projection", body)
		}
	}
	reader := server.securityUpdateEvidenceQuery.(packageUpdateFixture)
	if value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), owner.actor.TenantID, owner.product.ID, owner.release.ID); err == nil || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
		t.Fatal("failed commit exposed a partial reader snapshot", value, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed report mutated stored records", err)
	}
	withoutRepositories := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	reader.catalogFixtureCommands = catalogFixtureCommands{ledger: withoutRepositories}
	if value, err := reader.Report(t.Context(), owner.actor, owner.product.ID, owner.release.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(value, packagedomain.SecurityUpdateEvidenceReport{}) || clock.calls != 0 {
		t.Fatal("missing repository used aggregate fallback or reached the clock", value, err)
	}
	var absent context.Context
	if value, err := reader.ReadSecurityUpdateSnapshot(absent, owner.actor.TenantID, owner.product.ID, owner.release.ID); !errors.Is(err, packagequery.ErrSecurityUpdateValidation) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
		t.Fatal("nil context returned report metadata", value, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := reader.ReadSecurityUpdateSnapshot(ctx, owner.actor.TenantID, owner.product.ID, owner.release.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) || clock.calls != 0 {
		t.Fatal("canceled reader returned report metadata or reached the clock", value, err)
	}
}
