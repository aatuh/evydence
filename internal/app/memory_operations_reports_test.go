package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func memoryOperationsReportFixture(t *testing.T) (*memoryUnitOfWork, packagequery.IncidentReportReader, operationsquery.RetentionReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	incidents, ok := tx.Repositories().Risk.(packagequery.IncidentReportReader)
	if !ok {
		t.Fatal("memory risk lacks focused incident report reader")
	}
	retention, ok := tx.Repositories().Governance.(operationsquery.RetentionReader)
	if !ok {
		t.Fatal("memory governance lacks focused retention report reader")
	}
	at := fixedNow()
	tx.state.Incidents["incident"] = domain.Incident{ID: "incident", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Title: "Incident", Severity: "high", Status: "closed", OpenedAt: at, ClosedAt: &at, SchemaVersion: "1", CreatedAt: at}
	for _, id := range []string{"b", "a"} {
		tx.state.IncidentTimelineEvents[id] = domain.IncidentTimelineEvent{ID: id, TenantID: "tenant", IncidentID: "incident", EventType: "noted", Summary: id, EvidenceID: "recorded-evidence", OccurredAt: at, SchemaVersion: "1", CreatedAt: at}
		tx.state.RemediationTasks[id] = domain.RemediationTask{ID: id, TenantID: "tenant", IncidentID: "incident", ReleaseID: "tenant-release", Title: id, Owner: "team", Status: "open", DueAt: &at, EvidenceID: "recorded-evidence", SchemaVersion: "1", CreatedAt: at}
		tx.state.LegalHolds[id] = domain.LegalHold{ID: id, TenantID: "tenant", ScopeType: "release", ScopeID: "tenant-release", Reason: id, Owner: "reviewer", ReleasedAt: &at, SchemaVersion: "1", CreatedAt: at}
		tx.state.RetentionOverrides[id] = domain.RetentionOverride{ID: id, TenantID: "tenant", ScopeType: "evidence", ScopeID: "tenant-evidence", Reason: id, Owner: "reviewer", RetentionUntil: at, SchemaVersion: "1", CreatedAt: at}
	}
	return tx, incidents, retention
}

func TestMemoryOperationsReportsKeepPublicFieldsOwnershipAndDetachedTimestamps(t *testing.T) {
	tx, incidents, retention := memoryOperationsReportFixture(t)
	foreign := tx.state.IncidentTimelineEvents["a"]
	foreign.ID = "foreign"
	foreign.TenantID = "foreign"
	tx.state.IncidentTimelineEvents[foreign.ID] = foreign
	unrelated := tx.state.RemediationTasks["a"]
	unrelated.ID = "unrelated"
	unrelated.IncidentID = "other"
	tx.state.RemediationTasks[unrelated.ID] = unrelated
	h := tx.state.LegalHolds["a"]
	h.ID = "foreign"
	h.TenantID = "foreign"
	tx.state.LegalHolds[h.ID] = h
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := incidents.ReadIncidentReport(t.Context(), "tenant", "incident")
	want, conversionErr := domain.IncidentToContextModel(tx.state.Incidents["incident"])
	if err != nil || conversionErr != nil || !reflect.DeepEqual(snapshot.Incident, want) || len(snapshot.Timeline) != 2 || len(snapshot.Tasks) != 2 || snapshot.Timeline[0].ID != "a" || snapshot.Tasks[0].ID != "a" {
		t.Fatal("incident snapshot lost public fields, filtering or tie order", err)
	}
	if !reflect.DeepEqual(snapshot.Timeline[0], operationsdomain.IncidentTimelineEvent(tx.state.IncidentTimelineEvents["a"])) || !reflect.DeepEqual(snapshot.Tasks[0], operationsdomain.RemediationTask(tx.state.RemediationTasks["a"])) {
		t.Fatal("incident child DTO changed")
	}
	*snapshot.Incident.ClosedAt = snapshot.Incident.ClosedAt.AddDate(1, 0, 0)
	*snapshot.Tasks[0].DueAt = snapshot.Tasks[0].DueAt.AddDate(1, 0, 0)
	snapshot.Timeline[0].Summary = "changed"
	r, err := retention.ReadRetentionRecords(t.Context(), "tenant", "", "")
	if err != nil || len(r.LegalHolds) != 2 || len(r.RetentionOverrides) != 2 || r.LegalHolds[0].ID != "a" || r.RetentionOverrides[0].ID != "a" || !reflect.DeepEqual(r.LegalHolds[0], operationsdomain.LegalHold(tx.state.LegalHolds["a"])) {
		t.Fatal("retention snapshot lost metadata, ownership or order", err)
	}
	*r.LegalHolds[0].ReleasedAt = r.LegalHolds[0].ReleasedAt.AddDate(1, 0, 0)
	r.RetentionOverrides[0].Reason = "changed"
	filtered, err := retention.ReadRetentionRecords(t.Context(), "tenant", "release", "tenant-release")
	if err != nil || len(filtered.LegalHolds) != 2 || len(filtered.RetentionOverrides) != 0 {
		t.Fatal("retention filters changed", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("report reads exposed aliases or changed repository state")
	}
}

func TestMemoryIncidentReportRejectsInvalidCurrentParentsAndStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*MemoryUnitOfWorkSnapshot)
		want   error
	}{
		{"foreign incident", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Incidents["incident"]
			v.TenantID = "foreign"
			s.Incidents[v.ID] = v
		}, packagequery.ErrIncidentReportNotFound},
		{"missing product", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Products, "tenant-product") }, packagequery.ErrIncidentReportNotFound},
		{"foreign product", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Products["tenant-product"]
			v.TenantID = "foreign"
			s.Products[v.ID] = v
		}, packagequery.ErrIncidentReportNotFound},
		{"cross-product release", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.ProductID = "foreign-product"
			s.Releases[v.ID] = v
		}, packagequery.ErrIncidentReportNotFound},
		{"missing release", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Releases, "tenant-release") }, packagequery.ErrIncidentReportNotFound},
		{"invalid status", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Incidents["incident"]
			v.Status = "invalid"
			s.Incidents[v.ID] = v
		}, packagequery.ErrIncidentReportProjection},
		{"invalid child identity", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.IncidentTimelineEvents["a"]
			v.ID = "other"
			s.IncidentTimelineEvents["a"] = v
		}, packagequery.ErrIncidentReportProjection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, reader, _ := memoryOperationsReportFixture(t)
			tc.change(&tx.state)
			v, err := reader.ReadIncidentReport(t.Context(), "tenant", "incident")
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(v, packagequery.IncidentReportSnapshot{}) {
				t.Fatal("invalid incident snapshot exposed data", err)
			}
		})
	}
}

func TestMemoryIncidentReportEnforcesCombinedCapacityWithoutPartialResults(t *testing.T) {
	tx, reader, _ := memoryOperationsReportFixture(t)
	tx.state.IncidentTimelineEvents = map[string]domain.IncidentTimelineEvent{}
	tx.state.RemediationTasks = map[string]domain.RemediationTask{}
	for i := range 4095 {
		id := fmt.Sprintf("event-%04d", i)
		tx.state.IncidentTimelineEvents[id] = domain.IncidentTimelineEvent{ID: id, TenantID: "tenant", IncidentID: "incident", OccurredAt: fixedNow()}
	}
	tx.state.RemediationTasks["task"] = domain.RemediationTask{ID: "task", TenantID: "tenant", IncidentID: "incident", CreatedAt: fixedNow()}
	if v, err := reader.ReadIncidentReport(t.Context(), "tenant", "incident"); err != nil || len(v.Timeline)+len(v.Tasks) != 4096 {
		t.Fatal("exact combined capacity rejected or truncated", err)
	}
	tx.state.RemediationTasks["excess"] = domain.RemediationTask{ID: "excess", TenantID: "tenant", IncidentID: "incident", CreatedAt: fixedNow()}
	if v, err := reader.ReadIncidentReport(t.Context(), "tenant", "incident"); !errors.Is(err, packagequery.ErrIncidentReportCapacity) || !reflect.DeepEqual(v, packagequery.IncidentReportSnapshot{}) {
		t.Fatal("excess combined capacity returned partial report", err)
	}
}

func TestMemoryOperationsReportsRejectCancelledMissingAndClosedReads(t *testing.T) {
	tx, incident, retention := memoryOperationsReportFixture(t)
	var missingContext context.Context
	if _, err := incident.ReadIncidentReport(missingContext, "tenant", "incident"); err == nil {
		t.Fatal("nil incident context accepted")
	}
	if _, err := retention.ReadRetentionRecords(missingContext, "tenant", "", ""); err == nil {
		t.Fatal("nil retention context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := incident.ReadIncidentReport(ctx, "tenant", "incident"); !errors.Is(err, context.Canceled) {
		t.Fatal("incident cancellation lost", err)
	}
	if _, err := retention.ReadRetentionRecords(ctx, "tenant", "", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("retention cancellation lost", err)
	}
	if _, err := incident.ReadIncidentReport(t.Context(), "foreign", "incident"); !errors.Is(err, packagequery.ErrIncidentReportNotFound) {
		t.Fatal("foreign incident returned", err)
	}
	if _, err := retention.ReadRetentionRecords(t.Context(), "missing", "", ""); err == nil {
		t.Fatal("missing retention tenant returned")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := incident.ReadIncidentReport(t.Context(), "tenant", "incident"); err == nil {
		t.Fatal("closed incident transaction accepted")
	}
	if _, err := retention.ReadRetentionRecords(t.Context(), "tenant", "", ""); err == nil {
		t.Fatal("closed retention transaction accepted")
	}
}
