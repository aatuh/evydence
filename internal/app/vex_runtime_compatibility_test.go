package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func TestLocalVEXUploadCompletesDecisionProcessingWithoutAnOutboxWorker(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0903","component":"pkg:generic/payments@1","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("UploadVulnerabilityScan: %v", err)
	}

	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-0903", []map[string]any{{"@id": "pkg:generic/payments@1"}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("UploadVEX: %v", err)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("GetVEXImportReport: %v", err)
	}
	if report.Status != "parsed" || report.DecisionsCreated != 1 || report.DecisionsSuperseded != 0 || stringSliceContains(report.Warnings, evidenceapp.VEXAsyncDecisionWarning) {
		t.Fatalf("local VEX report = %#v, want synchronously parsed decision result", report)
	}
	active := true
	decisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Active: &active})
	if err != nil {
		t.Fatalf("ListVulnerabilityDecisions: %v", err)
	}
	if len(decisions) != 1 || decisions[0].FindingID != scan.Findings[0].ID || decisions[0].VEXDocumentID != vex.ID || decisions[0].Status != decisionStatusFixed || decisions[0].Source != "vex" {
		t.Fatalf("local VEX decisions = %#v", decisions)
	}
	readiness, err := ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("ReleaseReadinessReport: %v", err)
	}
	if len(readiness.BlockingFindings) != 0 {
		t.Fatalf("local VEX decision was not visible to readiness: %#v", readiness.BlockingFindings)
	}
}

func TestLocalCycloneDXVEXPreservesOriginalStatementIndexes(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	vex, err := ledger.UploadCycloneDXVEX(ctx, actor, release.ID, artifact.ID, []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"vulnerabilities":[
			{"analysis":{"state":"resolved","justification":"fixed_in_release"}},
			{"id":"CVE-2026-3903","affects":[{"ref":"pkg:generic/missing@1"}],"analysis":{"state":"resolved","justification":"fixed_in_release"}}
		]
	}`))
	if err != nil {
		t.Fatalf("UploadCycloneDXVEX: %v", err)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("GetVEXImportReport: %v", err)
	}
	if report.Status != "parsed" || len(report.InvalidStatements) != 1 || report.InvalidStatements[0].StatementIndex != 1 || len(report.MappingFailures) != 1 || report.MappingFailures[0].StatementIndex != 2 {
		t.Fatalf("local CycloneDX VEX report = %#v", report)
	}
}

func TestWorkerOwnedVEXModeRejectsMissingOutboxInsteadOfDiscardingJob(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, WorkerOwnedParserSideEffects: true})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	_, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-4903", []map[string]any{{"@id": "pkg:generic/payments@1"}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("UploadVEX error = %v, want fail-closed missing outbox error", err)
	}
}

func TestDurableVEXReadsRefreshWorkerCommittedStateAndPreserveTenantIsolation(t *testing.T) {
	ctx := context.Background()
	store := &memoryWorkerProjectionStore{MemoryStore: NewMemoryStore()}
	outbox := &recordingOutbox{}
	ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store, Outbox: outbox})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-1903","component":"pkg:generic/payments@1","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("UploadVulnerabilityScan: %v", err)
	}
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-1903", []map[string]any{{"@id": "pkg:generic/payments@1"}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("UploadVEX: %v", err)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("LoadState ok=%v err=%v", ok, err)
	}
	var reportID string
	for id, report := range state.VEXImportReports {
		if report.VEXDocumentID == vex.ID {
			reportID = id
			report.Status = "parsed"
			report.DecisionsCreated = 1
			report.UpdatedAt = fixedNow().Add(time.Minute)
			state.VEXImportReports[id] = report
			break
		}
	}
	if reportID == "" {
		t.Fatal("durable VEX import report missing")
	}
	workerDecision := domain.VulnerabilityDecision{
		ID: "vd_worker", TenantID: actor.TenantID, FindingID: scan.Findings[0].ID, ScanID: scan.ID,
		ReleaseID: release.ID, Vulnerability: scan.Findings[0].Vulnerability, Component: scan.Findings[0].Component,
		Status: decisionStatusFixed, Justification: "fixed_in_release", ImpactStatement: "patched before release",
		CustomerVisible: true, Source: "vex", EvidenceID: vex.EvidenceID, EvidenceIDs: []string{vex.EvidenceID},
		VEXDocumentID: vex.ID, ApprovedBy: actor.KeyID, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: fixedNow(),
	}
	state.Decisions[workerDecision.ID] = workerDecision
	state.Decisions["vd_foreign"] = domain.VulnerabilityDecision{
		ID: "vd_foreign", TenantID: "ten_foreign", ReleaseID: release.ID, FindingID: scan.Findings[0].ID,
		Status: decisionStatusFixed, Source: "vex", SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: fixedNow(),
	}
	durableVEX := state.VEXDocuments[vex.ID]
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatalf("SaveState worker projection: %v", err)
	}
	ledger.mu.Lock()
	staleVEX := ledger.vexDocuments[vex.ID]
	staleVEX.Author = ""
	ledger.vexDocuments[vex.ID] = staleVEX
	ledger.mu.Unlock()
	flow, err := ledger.ReleaseEvidenceFlowPlan(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("ReleaseEvidenceFlowPlan first refresh: %v", err)
	}
	if flow.Counts["vulnerability_decisions"] != 1 {
		t.Fatalf("first flow decision count = %d, want 1", flow.Counts["vulnerability_decisions"])
	}
	ledger.mu.Lock()
	delete(ledger.decisions, workerDecision.ID)
	ledger.mu.Unlock()
	securitySummary, err := ledger.ReleaseSecuritySummary(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("ReleaseSecuritySummary first refresh: %v", err)
	}
	if securitySummary.DecisionsByStatus[decisionStatusFixed] != 1 {
		t.Fatalf("first security summary decisions = %#v, want fixed decision", securitySummary.DecisionsByStatus)
	}

	gotVEX, err := ledger.GetVEXDocument(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("GetVEXDocument: %v", err)
	}
	if gotVEX.Author != durableVEX.Author || gotVEX.Author == "" {
		t.Fatalf("GetVEXDocument author = %q, want refreshed worker projection %q", gotVEX.Author, durableVEX.Author)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("GetVEXImportReport: %v", err)
	}
	if report.ID != reportID || report.Status != "parsed" || report.DecisionsCreated != 1 {
		t.Fatalf("refreshed VEX report = %#v", report)
	}
	active := true
	decisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Active: &active})
	if err != nil {
		t.Fatalf("ListVulnerabilityDecisions: %v", err)
	}
	if len(decisions) != 1 || decisions[0].ID != workerDecision.ID {
		t.Fatalf("tenant-scoped refreshed decisions = %#v", decisions)
	}
	summary, err := ledger.VulnerabilityDecisionSummaryReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("VulnerabilityDecisionSummaryReport: %v", err)
	}
	if len(summary.Decisions) != 1 || summary.Decisions[0].ID != workerDecision.ID {
		t.Fatalf("tenant-scoped refreshed summary = %#v", summary.Decisions)
	}
	readiness, err := ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("ReleaseReadinessReport: %v", err)
	}
	if len(readiness.BlockingFindings) != 0 {
		t.Fatalf("worker decision was not visible to readiness: %#v", readiness.BlockingFindings)
	}
}

type failingRefreshStore struct {
	*memoryWorkerProjectionStore
	err error
}

func (s *failingRefreshStore) LoadWorkerProjection(ctx context.Context, tenantID string) (WorkerProjection, error) {
	if s.err != nil {
		return WorkerProjection{}, s.err
	}
	return s.memoryWorkerProjectionStore.LoadWorkerProjection(ctx, tenantID)
}

func TestDurableVEXReadFailsClosedWhenRefreshFails(t *testing.T) {
	ctx := context.Background()
	store := &failingRefreshStore{memoryWorkerProjectionStore: &memoryWorkerProjectionStore{MemoryStore: NewMemoryStore()}}
	ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store, Outbox: &recordingOutbox{}})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-2903", []map[string]any{{"@id": "pkg:generic/payments@1"}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("UploadVEX: %v", err)
	}
	want := errors.New("durable refresh failed")
	store.err = want
	if _, err := ledger.GetVEXImportReport(ctx, actor, vex.ID); !errors.Is(err, want) {
		t.Fatalf("GetVEXImportReport error = %v, want refresh failure", err)
	}
}

type memoryWorkerProjectionStore struct{ *MemoryStore }

func (s *memoryWorkerProjectionStore) LoadWorkerProjection(ctx context.Context, tenantID string) (WorkerProjection, error) {
	state, ok, err := s.LoadState(ctx)
	if err != nil || !ok {
		return WorkerProjection{}, err
	}
	projection := WorkerProjection{}
	for _, sbom := range state.SBOMs {
		if sbom.TenantID == tenantID {
			projection.SBOMs = append(projection.SBOMs, sbom)
		}
	}
	for _, scan := range state.Scans {
		if scan.TenantID == tenantID {
			projection.Scans = append(projection.Scans, scan)
		}
	}
	for _, contract := range state.Contracts {
		if contract.TenantID == tenantID {
			projection.Contracts = append(projection.Contracts, contract)
		}
	}
	for _, document := range state.VEXDocuments {
		if document.TenantID == tenantID {
			projection.VEXDocuments = append(projection.VEXDocuments, document)
		}
	}
	for _, report := range state.VEXImportReports {
		if report.TenantID == tenantID {
			projection.VEXImportReports = append(projection.VEXImportReports, report)
		}
	}
	for _, attestation := range state.BuildAttestations {
		if attestation.TenantID == tenantID {
			projection.BuildAttestations = append(projection.BuildAttestations, attestation)
		}
	}
	for _, decision := range state.Decisions {
		if decision.TenantID == tenantID {
			projection.VulnerabilityDecisions = append(projection.VulnerabilityDecisions, decision)
		}
	}
	projection.AuditChainEntries = append(projection.AuditChainEntries, state.Chain[tenantID]...)
	return projection, nil
}
