package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestVEXCompletionFixtureCommitsRealDecisionsAuditAndReportOrNothing(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	before, err := factory.base.Snapshot()
	if err != nil || before.VEXImportReports[owner.report.ID].Status != "accepted" || len(before.Decisions) != 0 {
		t.Fatal("fixture did not record an actual pending worker request", err)
	}
	factory.fail = true
	if err := completeVEXFixtureJob(t.Context(), factory, before, owner.vex.ID); err == nil {
		t.Fatal("failed worker transaction was reported complete")
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed worker commit published decisions, audit or report", err)
	}
	factory.fail = false
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := completeVEXFixtureJob(ctx, factory, before, owner.vex.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("worker fixture ignored cancellation", err)
	}
	forged, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for id, job := range forged.OutboxJobs {
		if job.Kind == "parse_vex" {
			job.Payload["evidence_id"] = "foreign-source"
			forged.OutboxJobs[id] = job
		}
	}
	if err := completeVEXFixtureJob(t.Context(), factory, forged, owner.vex.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatal("worker fixture accepted a forged source binding", err)
	}
	after, err = factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("canceled or forged worker request changed state", err)
	}
	if err := completeVEXFixtureJob(t.Context(), factory, before, owner.vex.ID); err != nil {
		t.Fatal("actual normalized request did not complete", err)
	}
	after, err = factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	report := after.VEXImportReports[owner.report.ID]
	if report.Status != "parsed" || report.DecisionsCreated != 1 || len(after.Decisions) != 1 || report.DecisionsSuperseded != 0 || len(report.MappingFailures) != 0 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("completion report did not match actual committed effects", report)
	}
	for _, decision := range after.Decisions {
		if decision.TenantID != owner.actor.TenantID || decision.ScanID != owner.scan.ID || decision.FindingID != owner.scan.Findings[0].ID || decision.Status != "affected" || decision.VEXDocumentID != owner.vex.ID || decision.EvidenceID != owner.vex.EvidenceID {
			t.Fatal("completion created an unrelated decision", decision)
		}
		entries := after.AuditEntries[owner.actor.TenantID]
		audit := entries[len(entries)-1]
		if audit.EntryType != "vulnerability_decision.created" || audit.SubjectType != "vulnerability_finding" || audit.SubjectID != decision.FindingID || audit.ActorID != decision.ApprovedBy || audit.PayloadHash != after.Evidence[owner.vex.EvidenceID].PayloadHash {
			t.Fatal("completion omitted the linked decision audit", audit)
		}
	}
	read := evidenceReadFixture{catalogFixtureCommands{ledger: ledger}}
	got, err := read.GetVEXImportReport(t.Context(), owner.actor, owner.vex.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertEvidenceFixtureJSON(t, vexImportReportFromQuery(got), report)
	if err := completeVEXFixtureJob(t.Context(), factory, after, owner.vex.ID); err != nil {
		t.Fatal("completed worker replay failed", err)
	}
	replayed, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, replayed) {
		t.Fatal("worker replay changed completed counts or duplicated effects", err)
	}
}
