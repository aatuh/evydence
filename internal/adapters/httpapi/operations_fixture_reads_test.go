package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestOperationsFixtureReportsKeepCurrentGrantsCompleteDTOsAndDetachedMetadata(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	for _, scope := range []operationsFixtureScope{owner, foreign} {
		if _, err := ledger.RecordIncidentTimelineEvent(t.Context(), scope.actor, scope.incident.ID, app.RecordIncidentTimelineInput{EventType: "noted", Summary: "Containment recorded", EvidenceID: scope.evidence.ID}); err != nil {
			t.Fatal(err)
		}
		due := time.Date(2026, 10, 8, 16, 0, 0, 0, time.UTC)
		if _, err := ledger.CreateRemediationTask(t.Context(), scope.actor, app.CreateRemediationTaskInput{IncidentID: scope.incident.ID, ReleaseID: scope.release.ID, Title: "Patch", Owner: "Security Team", DueAt: &due, EvidenceID: scope.evidence.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.CreateLegalHold(t.Context(), scope.actor, app.CreateLegalHoldInput{ScopeType: "release", ScopeID: scope.release.ID, Reason: "Review", Owner: "Legal Team"}); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.CreateRetentionOverride(t.Context(), scope.actor, app.CreateRetentionOverrideInput{ScopeType: "evidence", ScopeID: scope.evidence.ID, Reason: "Review", Owner: "Security Team", RetentionUntil: due}); err != nil {
			t.Fatal(err)
		}
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
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
	wantIncident, err := ledger.IncidentReport(t.Context(), human, owner.incident.ID)
	if err != nil || !reflect.DeepEqual(incident.Data, wantIncident) || len(incident.Data.Timeline) != 1 || len(incident.Data.Tasks) != 1 || len(incident.Data.LinkedEvidence) != 2 {
		t.Fatal("incident DTO lost owned timeline/tasks/evidence/assumptions", err)
	}
	retentionResponse := getRaw(t, server, "fixture-auth", "/v1/reports/retention", 200)
	var retention struct {
		Data domain.RetentionReport `json:"data"`
	}
	if err := json.Unmarshal(retentionResponse.Body.Bytes(), &retention); err != nil {
		t.Fatal(err)
	}
	wantRetention, err := ledger.RetentionReport(t.Context(), human, "", "")
	if err != nil || !reflect.DeepEqual(retention.Data, wantRetention) || len(retention.Data.LegalHolds) != 1 || len(retention.Data.RetentionOverrides) != 1 {
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
	fixture := catalogFixtureCommands{ledger: ledger}
	projected, err := (incidentReportFixture{fixture}).Report(t.Context(), human, owner.incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	*projected.Tasks[0].DueAt = projected.Tasks[0].DueAt.AddDate(1, 0, 0)
	projected.Timeline[0].Summary = "modified"
	projected.LinkedEvidence[0] = "modified"
	projected.Assumptions[0] = "modified"
	projectedRetention, err := (retentionReportFixture{fixture}).Report(t.Context(), human, "", "")
	if err != nil {
		t.Fatal(err)
	}
	projectedRetention.LegalHolds[0].Owner = "modified"
	projectedRetention.RetentionOverrides[0].Reason = "modified"
	projectedRetention.Limitations[0] = "modified"
	again, err := ledger.IncidentReport(t.Context(), human, owner.incident.ID)
	if err != nil || !reflect.DeepEqual(wantIncident, again) {
		t.Fatal("incident fixture exposed stored aliases", err)
	}
	againRetention, err := ledger.RetentionReport(t.Context(), human, "", "")
	if err != nil || !reflect.DeepEqual(wantRetention, againRetention) {
		t.Fatal("retention fixture exposed stored aliases", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (incidentReportFixture{fixture}).Report(cancelled, human, owner.incident.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled incident report accepted", err)
	}
	if _, err := (retentionReportFixture{fixture}).Report(cancelled, human, "", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled retention report accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("report/denial or returned metadata mutation changed state", err)
	}
}
