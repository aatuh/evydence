package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestOperationsFixtureReportsKeepCurrentGrantsCompleteDTOsAndDetachedMetadata(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	markers := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) })}
	var ownTimeline domain.IncidentTimelineEvent
	var ownTask domain.RemediationTask
	var ownHold domain.LegalHold
	var ownOverride domain.RetentionOverride
	for _, scope := range []operationsFixtureScope{owner, foreign} {
		timeline, err := ledger.RecordIncidentTimelineEvent(t.Context(), scope.actor, scope.incident.ID, app.RecordIncidentTimelineInput{EventType: "noted", Summary: "Containment recorded", EvidenceID: scope.evidence.ID})
		if err != nil {
			t.Fatal(err)
		}
		due := time.Date(2026, 10, 8, 16, 0, 0, 0, time.UTC)
		task, err := ledger.CreateRemediationTask(t.Context(), scope.actor, app.CreateRemediationTaskInput{IncidentID: scope.incident.ID, ReleaseID: scope.release.ID, Title: "Patch", Owner: "Security Team", DueAt: &due, EvidenceID: scope.evidence.ID})
		if err != nil {
			t.Fatal(err)
		}
		hold, err := markers.CreateLegalHold(t.Context(), scope.actor, operationsapp.RetentionMarkerInput{ScopeType: "release", ScopeID: scope.release.ID, Reason: "Review", Owner: "Legal Team"})
		if err != nil {
			t.Fatal(err)
		}
		override, err := markers.CreateRetentionOverride(t.Context(), scope.actor, operationsapp.RetentionOverrideInput{RetentionMarkerInput: operationsapp.RetentionMarkerInput{ScopeType: "evidence", ScopeID: scope.evidence.ID, Reason: "Review", Owner: "Security Team"}, RetentionUntil: due})
		if err != nil {
			t.Fatal(err)
		}
		if scope.actor.TenantID == owner.actor.TenantID {
			ownTimeline, ownTask, ownHold, ownOverride = timeline, task, domain.LegalHold(hold), domain.RetentionOverride(override)
		}
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	fixture := catalogFixtureCommands{ledger: ledger}
	incidentQuery := incidentReportFixture{catalogFixtureCommands: fixture, now: now}
	retentionQuery := retentionReportFixture{catalogFixtureCommands: fixture, now: now}
	server.incidentReportQuery, server.retentionQuery = incidentQuery, retentionQuery
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"incident:read", "admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"admin"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"incident:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/reports/incident-package?incident_id=" + owner.incident.ID
	response := getRaw(t, server, "fixture-auth", path, 200)
	var incident struct {
		Data domain.IncidentReport `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &incident); err != nil {
		t.Fatal(err)
	}
	wantIncident := domain.IncidentReport{ReportType: "incident_package", TemplateVersion: "incident-package.v1.0.0", IncidentID: owner.incident.ID, Result: "open", Timeline: []domain.IncidentTimelineEvent{ownTimeline}, Tasks: []domain.RemediationTask{ownTask}, LinkedEvidence: []string{owner.evidence.ID, owner.evidence.ID}, Assumptions: []string{"Incident evidence is limited to records stored in this Evydence tenant."}, Limitations: []string{"This report organizes incident evidence and does not prove root cause completeness or remediation sufficiency."}, GeneratedAt: at}
	if !reflect.DeepEqual(incident.Data, wantIncident) || len(incident.Data.Timeline) != 1 || len(incident.Data.Tasks) != 1 || len(incident.Data.LinkedEvidence) != 2 {
		t.Fatal("incident DTO lost owned timeline/tasks/evidence/assumptions", err)
	}
	retentionResponse := getRaw(t, server, "fixture-auth", "/v1/reports/retention", 200)
	var retention struct {
		Data domain.RetentionReport `json:"data"`
	}
	if err := json.Unmarshal(retentionResponse.Body.Bytes(), &retention); err != nil {
		t.Fatal(err)
	}
	wantRetention := domain.RetentionReport{ReportType: "retention", LegalHolds: []domain.LegalHold{ownHold}, RetentionOverrides: []domain.RetentionOverride{ownOverride}, Limitations: []string{"Retention reports describe Evydence records and do not replace external storage lifecycle verification."}, GeneratedAt: at}
	if !reflect.DeepEqual(retention.Data, wantRetention) || len(retention.Data.LegalHolds) != 1 || len(retention.Data.RetentionOverrides) != 1 {
		t.Fatal("retention DTO lost owned markers/limitations", err)
	}
	getRaw(t, server, "fixture-auth", "/v1/reports/incident-package?incident_id="+foreign.incident.ID, 404)
	getRaw(t, server, "fixture-auth", path+"&incident_id="+foreign.incident.ID, 400)
	filtered := getRaw(t, server, "fixture-auth", "/v1/reports/retention?scope_type=release&scope_id="+owner.release.ID, 200)
	var filteredRetention struct {
		Data domain.RetentionReport `json:"data"`
	}
	if err := json.Unmarshal(filtered.Body.Bytes(), &filteredRetention); err != nil || len(filteredRetention.Data.LegalHolds) != 1 || len(filteredRetention.Data.RetentionOverrides) != 0 || filteredRetention.Data.ScopeType != "release" || filteredRetention.Data.ScopeID != owner.release.ID {
		t.Fatal("retention filters changed", err)
	}
	auth.actor.ResourceGrants = nil
	getRaw(t, server, "fixture-auth", path, 403)
	getRaw(t, server, "fixture-auth", "/v1/reports/retention", 403)
	auth.actor = human
	projected, err := incidentQuery.Report(t.Context(), human, owner.incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	*projected.Tasks[0].DueAt = projected.Tasks[0].DueAt.AddDate(1, 0, 0)
	projected.Timeline[0].Summary = "modified"
	projected.LinkedEvidence[0] = "modified"
	projected.Assumptions[0] = "modified"
	projectedRetention, err := retentionQuery.Report(t.Context(), human, "", "")
	if err != nil {
		t.Fatal(err)
	}
	projectedRetention.LegalHolds[0].Owner = "modified"
	projectedRetention.RetentionOverrides[0].Reason = "modified"
	projectedRetention.Limitations[0] = "modified"
	again, err := incidentQuery.Report(t.Context(), human, owner.incident.ID)
	if err != nil || !reflect.DeepEqual(wantIncident, incidentReportFromQuery(again)) {
		t.Fatal("incident fixture exposed stored aliases", err)
	}
	againRetention, err := retentionQuery.Report(t.Context(), human, "", "")
	if err != nil || !reflect.DeepEqual(wantRetention, retentionReportFromQuery(againRetention)) {
		t.Fatal("retention fixture exposed stored aliases", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (incidentReportFixture{catalogFixtureCommands: fixture}).Report(cancelled, human, owner.incident.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled incident report accepted", err)
	}
	if _, err := (retentionReportFixture{catalogFixtureCommands: fixture}).Report(cancelled, human, "", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled retention report accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("report/denial or returned metadata mutation changed state", err)
	}
}
