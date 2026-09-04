package app

import (
	"context"
	"errors"
	"testing"
)

type failingParserReleaseStore struct {
	err       error
	mutations []ReleaseLedgerMutation
}

func (s *failingParserReleaseStore) LoadState(context.Context) (PersistedState, bool, error) {
	return PersistedState{}, false, nil
}

func (s *failingParserReleaseStore) SaveState(context.Context, PersistedState) error {
	return s.err
}

func (s *failingParserReleaseStore) ApplyReleaseLedgerMutation(_ context.Context, mutation ReleaseLedgerMutation) error {
	s.mutations = append(s.mutations, mutation)
	return s.err
}

func TestParserCompatibilityTransactionBuffersOutboxAndRollsBackPublication(t *testing.T) {
	ctx := context.Background()
	outbox := &recordingOutbox{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Outbox: outbox})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	store := &failingParserReleaseStore{err: errors.New("release mutation failed")}
	ledger.store = store
	beforeEvidence, beforeSBOMs, beforeAudit := len(ledger.evidence), len(ledger.sboms), len(ledger.chain[actor.TenantID])

	_, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`))
	if !errors.Is(err, store.err) {
		t.Fatalf("UploadSBOM error = %v, want persistence failure", err)
	}
	if len(ledger.evidence) != beforeEvidence || len(ledger.sboms) != beforeSBOMs || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatalf("failed compatibility transaction published state: evidence=%d sboms=%d audit=%d", len(ledger.evidence), len(ledger.sboms), len(ledger.chain[actor.TenantID]))
	}
	if len(outbox.jobs) != 0 {
		t.Fatalf("release-mutation store should own atomic outbox persistence: %#v", outbox.jobs)
	}
	if len(store.mutations) != 1 || !releaseMutationHasOutbox(store.mutations[0], "parse_sbom") || len(store.mutations[0].Evidence) == 0 || len(store.mutations[0].SBOMs) == 0 {
		t.Fatalf("buffered release mutation = %#v", store.mutations)
	}
}

func TestVEXCompatibilityTransactionRollsBackDocumentReportAuditAndJob(t *testing.T) {
	ctx := context.Background()
	outbox := &recordingOutbox{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Outbox: outbox})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	store := &failingParserReleaseStore{err: errors.New("release mutation failed")}
	ledger.store = store
	beforeEvidence, beforeVEX, beforeReports, beforeAudit := len(ledger.evidence), len(ledger.vexDocuments), len(ledger.vexImportReports), len(ledger.chain[actor.TenantID])

	_, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-0903", []map[string]any{{"@id": "pkg:generic/api@1"}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if !errors.Is(err, store.err) {
		t.Fatalf("UploadVEX error = %v, want persistence failure", err)
	}
	if len(ledger.evidence) != beforeEvidence || len(ledger.vexDocuments) != beforeVEX || len(ledger.vexImportReports) != beforeReports || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatalf("failed compatibility transaction published VEX state: evidence=%d vex=%d reports=%d audit=%d", len(ledger.evidence), len(ledger.vexDocuments), len(ledger.vexImportReports), len(ledger.chain[actor.TenantID]))
	}
	if len(outbox.jobs) != 0 {
		t.Fatalf("release-mutation store should own atomic outbox persistence: %#v", outbox.jobs)
	}
	if len(store.mutations) != 1 || !releaseMutationHasOutbox(store.mutations[0], "parse_vex") || len(store.mutations[0].Evidence) == 0 || len(store.mutations[0].VEXDocuments) == 0 || len(store.mutations[0].VEXImportReports) == 0 || len(store.mutations[0].VulnerabilityDecisions) != 0 {
		t.Fatalf("buffered VEX release mutation = %#v", store.mutations)
	}
	mutation := store.mutations[0]
	var parseJob OutboxJob
	for _, job := range mutation.OutboxJobs {
		if job.Kind == "parse_vex" {
			parseJob = job
		}
	}
	if parseJob.ID == "" || parseJob.Payload["payload_ref"] != "" {
		t.Fatalf("buffered no-object VEX job = %#v", parseJob)
	}
	statements := requireVEXDecisionRequest(t, parseJob.Payload, 1)
	if statements[0].StatementIndex != 1 || statements[0].Vulnerability != "CVE-2026-0903" || statements[0].Status != decisionStatusFixed {
		t.Fatalf("buffered normalized VEX decision request = %#v", statements)
	}
}
