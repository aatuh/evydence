package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestReleaseSummaryNativeFixtureDiscardsProjectionOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedRiskReportFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt}
	server.bindReleaseSummaryFixtureClock(clock.Now)
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	rollbacks, begins := factory.rollbacks, factory.beginCalls
	path := "/v1/releases/" + owner.release.ID + "/security-summary"
	body := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
	var problem map[string]any
	if err := json.Unmarshal([]byte(body), &problem); err != nil {
		t.Fatal(err)
	}
	if factory.rollbacks != rollbacks+1 || factory.beginCalls != begins+1 || clock.calls != 1 || problem["instance"] != path || problem["data"] != nil || strings.Contains(body, "private-query") || strings.Contains(body, "missing_required_decisions") || strings.Contains(body, owner.product.ID) {
		t.Fatal("failed summary commit exposed partial data, retained transaction or evaluated after failure", body)
	}
	if v, err := server.releaseSecuritySummaryQuery.Summary(t.Context(), owner.actor, owner.release.ID); err == nil || !reflect.DeepEqual(v, riskdomain.ReleaseSecuritySummary{}) {
		t.Fatal("failed summary returned partial DTO", v, err)
	}
	reader := server.releaseSecuritySummaryQuery.(releaseSummaryNativeFixture)
	if v, err := reader.ReadReleaseSecuritySummarySnapshot(t.Context(), owner.actor.TenantID, owner.release.ID); err == nil || !reflect.DeepEqual(v, riskquery.ReleaseSecuritySummarySnapshot{}) {
		t.Fatal("failed summary snapshot returned partial projection", v, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || clock.calls != 3 {
		t.Fatal("failed summary changed state or used final evaluation clock", err)
	}
}

func TestReleaseSummaryNativeFixtureRequiresRepositoryAndPreservesExplicitPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	owner := seedRiskReportFixtureParentScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt}
	server.bindReleaseSummaryFixtureClock(clock.Now)
	if v, err := server.releaseSecuritySummaryQuery.Summary(t.Context(), owner.actor, owner.release.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, riskdomain.ReleaseSecuritySummary{}) || clock.calls != 0 {
		t.Fatal("summary without repositories fell back to cached aggregate", v, err)
	}
	reader := server.releaseSecuritySummaryQuery.(releaseSummaryNativeFixture)
	var missingContext context.Context
	if v, err := reader.ReadReleaseSecuritySummarySnapshot(missingContext, owner.actor.TenantID, owner.release.ID); !errors.Is(err, riskquery.ErrValidation) || !reflect.DeepEqual(v, riskquery.ReleaseSecuritySummarySnapshot{}) {
		t.Fatal("nil summary context was accepted", v, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := reader.ReadReleaseSecuritySummarySnapshot(ctx, owner.actor.TenantID, owner.release.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, riskquery.ReleaseSecuritySummarySnapshot{}) || clock.calls != 0 {
		t.Fatal("cancelled summary entered repository or clock", v, err)
	}
	mock := &securitySummaryHTTPFake{}
	server.releaseSecuritySummaryQuery = mock
	server.bindLegacyLedgerFixture(ledger)
	server.bindReleaseSummaryFixtureClock(clock.Now)
	if server.releaseSecuritySummaryQuery != mock {
		t.Fatal("rebinding replaced explicit summary query")
	}
}
