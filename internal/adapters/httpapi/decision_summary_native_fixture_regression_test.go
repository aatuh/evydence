package httpapi

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestDecisionSummaryFixtureUsesCurrentRepositoryAndFailsClosed(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }})
	owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("summary consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/reports/vulnerability-decision-summary?release_id=" + owner.release.ID
	begins := factory.beginCalls
	response := getRaw(t, server, "fixture", path, http.StatusOK).Body.String()
	if factory.beginCalls != begins+1 || !strings.Contains(response, owner.head.ID) || strings.Contains(response, "private triage") {
		t.Fatal("summary lost current visible head or disclosed private notes", response)
	}
	factory.fail = true
	response = getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
	for _, private := range []string{"private-query-commit-secret", "private triage", owner.head.ID, `"data"`} {
		if strings.Contains(response, private) {
			t.Fatal("failed summary commit disclosed partial data or diagnostics", response)
		}
	}
	factory.fail = false
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("summary query changed repository data", err)
	}
}
