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
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestOperationsReportNativeFixturesReadCurrentStateAndDiscardFailedCommit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	if _, err := (operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).RecordIncidentTimelineEvent(t.Context(), owner.actor, owner.incident.ID, operationsapp.RecordIncidentTimelineInput{EventType: "noted", Summary: "Recorded", EvidenceID: owner.evidence.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := (operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateLegalHold(t.Context(), owner.actor, operationsapp.RetentionMarkerInput{ScopeType: "release", ScopeID: owner.release.ID, Reason: "Review", Owner: "Reviewer"}); err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("report used aggregate clock") }})
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	incident := incidentReportFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, now: clock.Now}
	retention := retentionReportFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, now: clock.Now}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := incident.Report(t.Context(), owner.actor, owner.incident.ID)
	if err != nil || v.IncidentID != owner.incident.ID || v.ReportType != "incident_package" || v.TemplateVersion != "incident-package.v1.0.0" || len(v.Timeline) != 1 || v.Timeline[0].Summary != "Recorded" || len(v.LinkedEvidence) != 1 || v.LinkedEvidence[0] != owner.evidence.ID || v.GeneratedAt != clock.at || clock.calls != 1 {
		t.Fatal("incident report used cached state or lost public fields/time", err)
	}
	r, err := retention.Report(t.Context(), owner.actor, "release", owner.release.ID)
	if err != nil || r.ReportType != "retention" || r.ScopeType != "release" || r.ScopeID != owner.release.ID || len(r.LegalHolds) != 1 || r.LegalHolds[0].Reason != "Review" || len(r.Limitations) == 0 || r.GeneratedAt != clock.at || clock.calls != 2 {
		t.Fatal("retention report used cached state or lost fields/time", err)
	}
	if _, err := incident.Report(t.Context(), owner.actor, foreign.incident.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign incident report disclosed data", err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"incident:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: owner.release.ID, Scopes: []string{"incident:read"}}}}
	if _, err := incident.Report(t.Context(), human, owner.incident.ID); err != nil {
		t.Fatal("current release grant denied incident report", err)
	}
	human.ResourceGrants = nil
	if _, err := incident.Report(t.Context(), human, owner.incident.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked incident report grant accepted", err)
	}
	human.Scopes = []string{"admin"}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"admin"}}}
	if _, err := retention.Report(t.Context(), human, "", ""); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("scoped admin exposed tenant retention inventory", err)
	}
	factory.fail = true
	calls := clock.calls
	if v, err := incident.Report(t.Context(), owner.actor, owner.incident.ID); err == nil || !reflect.DeepEqual(v, packagedomain.IncidentReport{}) {
		t.Fatal("failed read commit exposed incident report", err)
	}
	if r, err := retention.Report(t.Context(), owner.actor, "", ""); err == nil || !reflect.DeepEqual(r, operationsdomain.RetentionReport{}) {
		t.Fatal("failed read commit exposed retention report", err)
	}
	if clock.calls != calls {
		t.Fatal("failed report generated timestamp")
	}
	server, err := newLegacyServerFixture(rebound)
	if err != nil {
		t.Fatal(err)
	}
	server.authn = &configuredAuthenticator{actor: owner.actor}
	for _, path := range []string{"/v1/reports/incident-package?incident_id=" + owner.incident.ID, "/v1/reports/retention"} {
		body := getRaw(t, server, "fixture", path, 500).Body.String()
		var problem map[string]any
		if err := json.Unmarshal([]byte(body), &problem); err != nil || problem["data"] != nil || strings.Contains(body, "private-query") || strings.Contains(body, "Recorded") || strings.Contains(body, owner.evidence.ID) {
			t.Fatal("failed report leaked state or internal error", err)
		}
	}
	factory.fail = false
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("report reads/denials/failed commits changed state", err)
	}
}

func TestOperationsReportNativeFixturesRequireRepositoriesAndPreserveExplicitPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	incident := incidentReportFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	retention := retentionReportFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	if v, err := incident.Report(t.Context(), a, "incident"); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, packagedomain.IncidentReport{}) {
		t.Fatal("missing repositories restored incident cache", err)
	}
	if v, err := retention.Report(t.Context(), a, "", ""); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, operationsdomain.RetentionReport{}) {
		t.Fatal("missing repositories restored retention cache", err)
	}
	var missingContext context.Context
	if _, err := incident.Report(missingContext, a, "incident"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil incident context accepted", err)
	}
	if _, err := retention.Report(missingContext, a, "", ""); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil retention context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := incident.Report(ctx, a, "incident"); !errors.Is(err, context.Canceled) {
		t.Fatal("incident cancellation lost", err)
	}
	if _, err := retention.Report(ctx, a, "", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("retention cancellation lost", err)
	}
	explicit := &incidentReportHTTPFake{}
	server := &Server{incidentReportQuery: explicit}
	server.bindOperationsFixtureQueries(ledger)
	if server.incidentReportQuery != explicit {
		t.Fatal("binding replaced explicit incident report query")
	}
	explicitRetention := &retentionQueryHTTPFake{}
	server = &Server{retentionQuery: explicitRetention}
	server.bindOperationsFixtureQueries(ledger)
	if server.retentionQuery != explicitRetention {
		t.Fatal("binding replaced explicit retention query")
	}
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	old := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	server = &Server{incidentReportQuery: incidentReportFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: old}, now: now}, retentionQuery: retentionReportFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: old}, now: now}}
	server.bindOperationsFixtureQueries(ledger)
	boundIncident, ok := server.incidentReportQuery.(incidentReportFixture)
	if !ok || boundIncident.ledger != ledger || boundIncident.now == nil || boundIncident.now() != at {
		t.Fatal("incident rebind discarded explicit clock")
	}
	boundRetention, ok := server.retentionQuery.(retentionReportFixture)
	if !ok || boundRetention.ledger != ledger || boundRetention.now == nil || boundRetention.now() != at {
		t.Fatal("retention rebind discarded explicit clock")
	}
}
