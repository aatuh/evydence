package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type fixedWorkerProjectionStore struct {
	projection WorkerProjection
	err        error
}

func (s fixedWorkerProjectionStore) LoadWorkerProjection(context.Context, string) (WorkerProjection, error) {
	return s.projection, s.err
}

func TestWorkerProjectionRejectsHostileEvidenceCoordinatesWithoutPartialPublish(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.SBOM, domain.Artifact)
	}{
		{
			name: "same-tenant artifact alias",
			mutate: func(sbom *domain.SBOM, other domain.Artifact) {
				sbom.ArtifactID = other.ID
			},
		},
		{
			name: "omitted release",
			mutate: func(sbom *domain.SBOM, _ domain.Artifact) {
				sbom.ReleaseID = ""
			},
		},
		{
			name: "foreign tenant",
			mutate: func(sbom *domain.SBOM, _ domain.Artifact) {
				sbom.TenantID = "ten_foreign"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
			actor, release, artifact := setupReleaseRiskFixture(t, ledger)
			other, err := ledger.RegisterArtifact(ctx, actor, "other.tar.gz", "application/gzip", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 10)
			if err != nil {
				t.Fatalf("RegisterArtifact: %v", err)
			}
			sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api"}]}`))
			if err != nil {
				t.Fatalf("UploadSBOM: %v", err)
			}
			before := cloneSBOMMap(ledger.sboms)
			hostile := sbom
			tt.mutate(&hostile, other)
			ledger.workerProjections = fixedWorkerProjectionStore{projection: WorkerProjection{SBOMs: []domain.SBOM{hostile}}}

			ledger.mu.Lock()
			err = ledger.refreshWorkerProjectionLocked(ctx, actor.TenantID)
			ledger.mu.Unlock()
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("refresh error = %v, want conflict", err)
			}
			if !reflect.DeepEqual(ledger.sboms, before) {
				t.Fatalf("failed refresh partially published SBOM state")
			}
		})
	}
}

func TestWorkerProjectionAcceptsPostgresNormalizedDecisionShape(t *testing.T) {
	createdAt := time.Date(2026, 9, 4, 12, 0, 0, 123456789, time.FixedZone("test", 2*60*60))
	reviewedAt := createdAt.Add(time.Minute)
	reviewDueAt := createdAt.Add(24 * time.Hour)
	existing := domain.VulnerabilityDecision{
		ID: "vd_projection", TenantID: "ten_projection", FindingID: "finding_projection", ScanID: "scan_projection",
		ReleaseID: "rel_projection", Vulnerability: "CVE-2026-0904", Component: "pkg:generic/api@1",
		Status: "fixed", Justification: "fixed_in_release", Source: "manual", SchemaVersion: domain.VulnerabilityDecisionVersion,
		ReviewedAt: &reviewedAt, ReviewDueAt: &reviewDueAt, CreatedAt: createdAt,
	}
	incoming := existing
	incoming.CreatedAt = incoming.CreatedAt.UTC().Truncate(time.Microsecond)
	incomingReviewedAt := incoming.ReviewedAt.UTC().Truncate(time.Microsecond)
	incomingReviewDueAt := incoming.ReviewDueAt.UTC().Truncate(time.Microsecond)
	incoming.ReviewedAt = &incomingReviewedAt
	incoming.ReviewDueAt = &incomingReviewDueAt
	incoming.EvidenceIDs = []string{}
	incoming.SupportingRefs = []domain.SubjectRef{}

	merged, err := mergeProjectedDecision(existing, incoming)
	if err != nil {
		t.Fatalf("mergeProjectedDecision: %v", err)
	}
	if merged.ID != existing.ID || !samePersistedTime(merged.CreatedAt, existing.CreatedAt) {
		t.Fatalf("merged decision = %#v", merged)
	}
}

func TestWorkerProjectionAllowsNewerFailedVEXClassificationAndRejectsRegression(t *testing.T) {
	createdAt := time.Date(2026, 9, 4, 10, 0, 0, 987654321, time.UTC)
	existing := domain.VEXImportReport{
		ID: "vex_report_projection", TenantID: "ten_projection", VEXDocumentID: "vex_projection", EvidenceID: "ev_projection",
		ParserVersion: ParserVersionOpenVEXJSON, Status: "failed", StatementCount: 1,
		FailureCode: "payload_read_failed", FailureDetail: "The VEX payload could not be read.",
		SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: createdAt, UpdatedAt: createdAt.Add(time.Second),
	}
	incoming := existing
	incoming.CreatedAt = incoming.CreatedAt.Truncate(time.Microsecond)
	incoming.UpdatedAt = incoming.UpdatedAt.Add(time.Second).Truncate(time.Microsecond)
	incoming.FailureCode = "parser_failed"
	incoming.FailureDetail = "The VEX payload could not be processed."

	merged, err := mergeProjectedVEXReport(existing, incoming)
	if err != nil {
		t.Fatalf("mergeProjectedVEXReport newer failure: %v", err)
	}
	if merged.FailureCode != incoming.FailureCode || merged.FailureDetail != incoming.FailureDetail {
		t.Fatalf("merged failure = %#v", merged)
	}

	parsed := incoming
	parsed.Status = "parsed"
	parsed.FailureCode = ""
	parsed.FailureDetail = ""
	parsed.UpdatedAt = incoming.UpdatedAt.Add(time.Second)
	parsedReport, err := mergeProjectedVEXReport(merged, parsed)
	if err != nil {
		t.Fatalf("mergeProjectedVEXReport parsed: %v", err)
	}
	regressed := parsedReport
	regressed.Status = "failed"
	regressed.FailureCode = "parser_failed"
	regressed.FailureDetail = "The VEX payload could not be processed."
	regressed.UpdatedAt = parsedReport.UpdatedAt.Add(time.Second)
	if _, err := mergeProjectedVEXReport(parsedReport, regressed); !errors.Is(err, ErrConflict) {
		t.Fatalf("parsed-to-failed error = %v, want conflict", err)
	}
}

func TestWorkerProjectionUsesVEXStateProgressionAcrossClockSkew(t *testing.T) {
	createdAt := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	accepted := domain.VEXImportReport{
		ID: "vex_report_clock_skew", TenantID: "ten_projection", VEXDocumentID: "vex_clock_skew", EvidenceID: "ev_clock_skew",
		ParserVersion: ParserVersionOpenVEXJSON, Status: "accepted", StatementCount: 1,
		SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: createdAt, UpdatedAt: createdAt.Add(30 * time.Second),
	}
	failed := accepted
	failed.Status = "failed"
	failed.FailureCode = "parser_failed"
	failed.FailureDetail = "The VEX payload could not be processed."
	failed.UpdatedAt = createdAt.Add(-time.Second)

	merged, err := mergeProjectedVEXReport(accepted, failed)
	if err != nil {
		t.Fatalf("accepted-to-failed merge across clock skew: %v", err)
	}
	if merged.Status != "failed" || merged.FailureCode != failed.FailureCode {
		t.Fatalf("merged report = %#v, want terminal failure", merged)
	}
	if merged.UpdatedAt.Before(accepted.UpdatedAt) {
		t.Fatalf("merged updated_at = %s, want monotonic timestamp at or after %s", merged.UpdatedAt, accepted.UpdatedAt)
	}

	parsed := failed
	parsed.Status = "parsed"
	parsed.FailureCode = ""
	parsed.FailureDetail = ""
	parsed.UpdatedAt = createdAt.Add(-2 * time.Second)
	merged, err = mergeProjectedVEXReport(merged, parsed)
	if err != nil {
		t.Fatalf("failed-to-parsed merge across clock skew: %v", err)
	}
	if merged.Status != "parsed" {
		t.Fatalf("merged status = %q, want parsed", merged.Status)
	}
	if merged.UpdatedAt.Before(accepted.UpdatedAt) {
		t.Fatalf("parsed updated_at = %s, want monotonic timestamp at or after %s", merged.UpdatedAt, accepted.UpdatedAt)
	}
}

func TestWorkerProjectionFailureBlocksImmutableBundleAndCustomerPackageCreation(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{
		Name: "worker projection", AllowedTypes: []string{"sbom", "vulnerability_scan", "vex", "vulnerability_decision"},
	})
	if err != nil {
		t.Fatalf("CreateRedactionProfile: %v", err)
	}
	want := errors.New("worker projection unavailable")
	ledger.workerProjections = fixedWorkerProjectionStore{err: want}

	if _, err := ledger.CreateReleaseBundle(ctx, actor, release.ID); !errors.Is(err, want) {
		t.Fatalf("CreateReleaseBundle error = %v, want projection failure", err)
	}
	if len(ledger.bundles) != 0 {
		t.Fatalf("bundle was published after projection failure: %#v", ledger.bundles)
	}
	if _, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID,
		Title: "blocked package", ExpiresAt: fixedNow().Add(24 * time.Hour),
	}); !errors.Is(err, want) {
		t.Fatalf("CreateCustomerSecurityPackage error = %v, want projection failure", err)
	}
	if len(ledger.customerPackages) != 0 {
		t.Fatalf("customer package was published after projection failure: %#v", ledger.customerPackages)
	}
}

func TestPublishCommittedAuditEntryKeepsAValidContiguousTenantPrefix(t *testing.T) {
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	first := projectionAuditEntry(t, "ten_audit_projection", 1, "", "ace_first")
	ledger.publishCommittedAuditEntryLocked(first)

	divergent := projectionAuditEntry(t, first.TenantID, 1, "", "ace_divergent")
	ledger.publishCommittedAuditEntryLocked(divergent)
	gap := projectionAuditEntry(t, first.TenantID, 3, "sha256:missing-predecessor", "ace_gap")
	ledger.publishCommittedAuditEntryLocked(gap)
	if got := ledger.chain[first.TenantID]; len(got) != 1 || got[0].ID != first.ID {
		t.Fatalf("divergence or gap corrupted prefix: %#v", got)
	}

	second := projectionAuditEntry(t, first.TenantID, 2, first.EntryHash, "ace_second")
	ledger.publishCommittedAuditEntryLocked(second)
	ledger.publishCommittedAuditEntryLocked(second)
	invalid := projectionAuditEntry(t, first.TenantID, 3, second.EntryHash, "ace_invalid")
	invalid.EntryHash = "sha256:invalid"
	ledger.publishCommittedAuditEntryLocked(invalid)
	if got := ledger.chain[first.TenantID]; len(got) != 2 || got[1].ID != second.ID {
		t.Fatalf("next, duplicate, or invalid publish result = %#v", got)
	}

	foreign := projectionAuditEntry(t, "ten_other", 1, "", "ace_foreign")
	ledger.publishCommittedAuditEntryLocked(foreign)
	if got := ledger.chain[foreign.TenantID]; len(got) != 1 || got[0].ID != foreign.ID {
		t.Fatalf("foreign tenant prefix = %#v", got)
	}
}

func TestWorkerProjectionRejectsAuthoritativeAuditChainShrink(t *testing.T) {
	tenantID := "ten_audit_shrink"
	first := projectionAuditEntry(t, tenantID, 1, "", "ace_first")
	second := projectionAuditEntry(t, tenantID, 2, first.EntryHash, "ace_second")

	for _, incoming := range [][]domain.AuditChainEntry{nil, {first}} {
		target := map[string][]domain.AuditChainEntry{tenantID: {first, second}}
		if err := mergeWorkerAuditChain(tenantID, incoming, target); !errors.Is(err, ErrConflict) {
			t.Fatalf("incoming length %d error = %v, want conflict", len(incoming), err)
		}
		if got := target[tenantID]; len(got) != 2 || got[1].ID != second.ID {
			t.Fatalf("incoming length %d changed local chain: %#v", len(incoming), got)
		}
	}
}

func TestWorkerProjectionRejectsAuthoritativeWorkerRowShrink(t *testing.T) {
	tests := []struct {
		name   string
		insert func(*Ledger)
	}{
		{name: "SBOM", insert: func(ledger *Ledger) {
			ledger.sboms["sbom_projection"] = domain.SBOM{ID: "sbom_projection", TenantID: "ten_projection"}
		}},
		{name: "vulnerability scan", insert: func(ledger *Ledger) {
			ledger.scans["scan_projection"] = domain.VulnerabilityScan{ID: "scan_projection", TenantID: "ten_projection"}
		}},
		{name: "OpenAPI contract", insert: func(ledger *Ledger) {
			ledger.contracts["oas_projection"] = domain.OpenAPIContract{ID: "oas_projection", TenantID: "ten_projection"}
		}},
		{name: "VEX document", insert: func(ledger *Ledger) {
			ledger.vexDocuments["vex_projection"] = domain.VEXDocument{ID: "vex_projection", TenantID: "ten_projection"}
		}},
		{name: "VEX import report", insert: func(ledger *Ledger) {
			ledger.vexImportReports["vex_report_projection"] = domain.VEXImportReport{ID: "vex_report_projection", TenantID: "ten_projection"}
		}},
		{name: "build attestation", insert: func(ledger *Ledger) {
			ledger.attestations["att_projection"] = domain.BuildAttestation{ID: "att_projection", TenantID: "ten_projection"}
		}},
		{name: "vulnerability decision", insert: func(ledger *Ledger) {
			ledger.decisions["vd_projection"] = domain.VulnerabilityDecision{ID: "vd_projection", TenantID: "ten_projection"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
			ledger.tenants["ten_projection"] = domain.Tenant{ID: "ten_projection"}
			test.insert(ledger)
			ledger.workerProjections = fixedWorkerProjectionStore{projection: WorkerProjection{}}

			ledger.mu.Lock()
			err := ledger.refreshWorkerProjectionLocked(context.Background(), "ten_projection")
			ledger.mu.Unlock()
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("refresh error = %v, want conflict", err)
			}
		})
	}
}

func TestWorkerProjectionRejectsParsedFieldRegression(t *testing.T) {
	createdAt := fixedNow()
	tests := []struct {
		name  string
		merge func() error
	}{
		{name: "SBOM spec version", merge: func() error {
			existing := domain.SBOM{ID: "sbom_projection", TenantID: "ten_projection", SpecVersion: "1.6", CreatedAt: createdAt}
			incoming := existing
			incoming.SpecVersion = ""
			_, err := mergeProjectedSBOM(existing, incoming)
			return err
		}},
		{name: "vulnerability scan parser", merge: func() error {
			existing := domain.VulnerabilityScan{
				ID: "scan_projection", TenantID: "ten_projection", Scanner: "trivy", Adapter: "trivy-json",
				AdapterVersion: "1.0.0", SourceSchema: "trivy-json.v1", TargetRef: "image@example", CreatedAt: createdAt,
			}
			incoming := existing
			incoming.Scanner = ""
			_, err := mergeProjectedScan(existing, incoming)
			return err
		}},
		{name: "OpenAPI path count", merge: func() error {
			existing := domain.OpenAPIContract{ID: "oas_projection", TenantID: "ten_projection", PathCount: 2, CreatedAt: createdAt}
			incoming := existing
			incoming.PathCount = 0
			_, err := mergeProjectedContract(existing, incoming)
			return err
		}},
		{name: "VEX author", merge: func() error {
			existing := domain.VEXDocument{ID: "vex_projection", TenantID: "ten_projection", Author: "security@example.test", CreatedAt: createdAt}
			incoming := existing
			incoming.Author = ""
			_, err := mergeProjectedVEXDocument(existing, incoming)
			return err
		}},
		{name: "build attestation predicate", merge: func() error {
			existing := domain.BuildAttestation{
				ID: "att_projection", TenantID: "ten_projection", PayloadType: "application/vnd.in-toto+json",
				PredicateType: "https://slsa.dev/provenance/v1", VerificationStatus: "structurally_valid", CreatedAt: createdAt,
			}
			incoming := existing
			incoming.PredicateType = ""
			_, err := mergeProjectedBuildAttestation(existing, incoming)
			return err
		}},
		{name: "vulnerability decision supersession", merge: func() error {
			existing := domain.VulnerabilityDecision{ID: "vd_projection", TenantID: "ten_projection", SupersededBy: "vd_replacement", CreatedAt: createdAt}
			incoming := existing
			incoming.SupersededBy = ""
			_, err := mergeProjectedDecision(existing, incoming)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.merge(); !errors.Is(err, ErrConflict) {
				t.Fatalf("merge error = %v, want conflict", err)
			}
		})
	}
}

func TestWorkerProjectionAllowsAcceptedToParsedProgression(t *testing.T) {
	createdAt := fixedNow()

	t.Run("zero-component SBOM", func(t *testing.T) {
		accepted := domain.SBOM{ID: "sbom_projection", TenantID: "ten_projection", Format: "cyclonedx", CreatedAt: createdAt}
		parsed := accepted
		parsed.SpecVersion = "1.6"
		merged, err := mergeProjectedSBOM(accepted, parsed)
		if err != nil || merged.SpecVersion != parsed.SpecVersion || merged.ComponentCount != 0 || len(merged.Components) != 0 {
			t.Fatalf("merged SBOM = %#v, err = %v", merged, err)
		}
	})

	t.Run("zero-finding vulnerability scan", func(t *testing.T) {
		accepted := domain.VulnerabilityScan{ID: "scan_projection", TenantID: "ten_projection", CreatedAt: createdAt}
		parsed := accepted
		parsed.Scanner = "trivy"
		parsed.Adapter = "trivy-json"
		parsed.AdapterVersion = "1.0.0"
		parsed.SourceSchema = "trivy-json.v1"
		parsed.TargetRef = "image@example"
		parsed.Summary = map[string]int{}
		parsed.Findings = []domain.VulnerabilityFinding{}
		merged, err := mergeProjectedScan(accepted, parsed)
		if err != nil || merged.Scanner != parsed.Scanner || merged.TargetRef != parsed.TargetRef || len(merged.Findings) != 0 {
			t.Fatalf("merged scan = %#v, err = %v", merged, err)
		}
	})

	t.Run("OpenAPI contract", func(t *testing.T) {
		accepted := domain.OpenAPIContract{ID: "oas_projection", TenantID: "ten_projection", CreatedAt: createdAt}
		parsed := accepted
		parsed.PathCount = 1
		parsed.Operations = []domain.OpenAPIOperation{{Path: "/health", Method: "get"}}
		merged, err := mergeProjectedContract(accepted, parsed)
		if err != nil || merged.PathCount != 1 || len(merged.Operations) != 1 {
			t.Fatalf("merged contract = %#v, err = %v", merged, err)
		}
	})

	t.Run("VEX document with optional author", func(t *testing.T) {
		accepted := domain.VEXDocument{ID: "vex_projection", TenantID: "ten_projection", CreatedAt: createdAt}
		parsed := accepted
		parsed.StatementCount = 1
		parsed.StatusSummary = map[string]int{"affected": 1}
		merged, err := mergeProjectedVEXDocument(accepted, parsed)
		if err != nil || merged.Author != "" || merged.StatementCount != 1 || merged.StatusSummary["affected"] != 1 {
			t.Fatalf("merged VEX document = %#v, err = %v", merged, err)
		}
	})

	t.Run("build attestation", func(t *testing.T) {
		accepted := domain.BuildAttestation{
			ID: "att_projection", TenantID: "ten_projection", PayloadHash: "sha256:payload", PayloadSize: 42,
			VerificationStatus: "accepted", CreatedAt: createdAt,
		}
		parsed := accepted
		parsed.PayloadType = "application/vnd.in-toto+json"
		parsed.PredicateType = "https://slsa.dev/provenance/v1"
		parsed.SubjectDigests = []string{"sha256:subject"}
		parsed.SignatureCount = 1
		parsed.VerificationStatus = "structurally_valid"
		merged, err := mergeProjectedBuildAttestation(accepted, parsed)
		if err != nil || merged.VerificationStatus != "structurally_valid" || merged.PayloadHash != accepted.PayloadHash || merged.PredicateType != parsed.PredicateType {
			t.Fatalf("merged attestation = %#v, err = %v", merged, err)
		}
	})

	t.Run("decision supersession", func(t *testing.T) {
		accepted := domain.VulnerabilityDecision{ID: "vd_projection", TenantID: "ten_projection", CreatedAt: createdAt}
		parsed := accepted
		parsed.SupersededBy = "vd_replacement"
		merged, err := mergeProjectedDecision(accepted, parsed)
		if err != nil || merged.SupersededBy != parsed.SupersededBy {
			t.Fatalf("merged decision = %#v, err = %v", merged, err)
		}
	})
}

func TestWorkerProjectionFailureBlocksAuditChainReadersAndSigners(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	want := errors.New("worker projection unavailable")
	ledger.workerProjections = fixedWorkerProjectionStore{err: want}

	tests := []struct {
		name string
		run  func() error
	}{
		{name: "verify subject", run: func() error { _, err := ledger.VerifySubject(ctx, actor, "audit_chain", ""); return err }},
		{name: "create merkle batch", run: func() error { _, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{}); return err }},
		{name: "verify merkle batch", run: func() error { _, err := ledger.VerifyMerkleBatch(ctx, actor, "missing"); return err }},
		{name: "export evidence bundle", run: func() error { _, err := ledger.ExportEvidenceBundle(ctx, actor, release.ID, nil); return err }},
		{name: "generate backup manifest", run: func() error { _, err := ledger.GenerateBackupManifest(ctx, actor); return err }},
		{name: "list audit log", run: func() error { _, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{}); return err }},
		{name: "metrics", run: func() error { _, err := ledger.Metrics(ctx, actor); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, want) {
				t.Fatalf("error = %v, want projection failure", err)
			}
		})
	}
}

func TestWorkerProjectionFailureBlocksWorkerBackedFindingConsumers(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	want := errors.New("worker projection unavailable")
	ledger.workerProjections = fixedWorkerProjectionStore{err: want}

	tests := []struct {
		name string
		run  func() error
	}{
		{name: "record vulnerability workflow", run: func() error {
			_, err := ledger.RecordVulnerabilityWorkflow(ctx, actor, RecordVulnerabilityWorkflowInput{
				FindingID: "finding_missing", Action: "reopened", Reason: "projection test",
			})
			return err
		}},
		{name: "vulnerability posture report", run: func() error {
			_, err := ledger.VulnerabilityPostureReport(ctx, actor, release.ID)
			return err
		}},
		{name: "create finding exception", run: func() error {
			_, err := ledger.CreateException(ctx, actor, CreateExceptionInput{
				ReleaseID: release.ID, FindingID: "finding_missing", Reason: "projection test",
				Owner: "security", ExpiresAt: fixedNow().Add(time.Hour),
			})
			return err
		}},
		{name: "create finding waiver", run: func() error {
			_, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{
				ScopeType: "finding", ScopeID: "finding_missing", Owner: "security",
				Risk: "accepted", Reason: "projection test", ExpiresAt: fixedNow().Add(time.Hour),
			})
			return err
		}},
		{name: "link worker-backed control evidence", run: func() error {
			_, err := ledger.LinkControlEvidence(ctx, actor, "control_missing", LinkControlEvidenceInput{
				EvidenceType: "vulnerability_scan", SubjectType: "vulnerability_scan",
				SubjectID: "scan_missing", Confidence: confidenceHigh,
			})
			return err
		}},
		{name: "create SBOM diff", run: func() error {
			_, err := ledger.CreateSBOMDiff(ctx, actor, CreateSBOMDiffInput{
				BaseSBOMID: "sbom_base", TargetSBOMID: "sbom_target",
			})
			return err
		}},
		{name: "create contract diff", run: func() error {
			_, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{
				BaseContractID: "contract_base", TargetContractID: "contract_target",
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, want) {
				t.Fatalf("error = %v, want projection failure", err)
			}
		})
	}
}

func TestWorkerProjectionPrefersActiveTransactionReader(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, _, _ := setupReleaseRiskFixture(t, ledger)
	external := &recordingWorkerProjectionStore{err: errors.New("nested projection reader used")}
	transaction := &recordingWorkerProjectionStore{projection: WorkerProjection{
		AuditChainEntries: append([]domain.AuditChainEntry(nil), ledger.chain[actor.TenantID]...),
	}}
	ledger.workerProjections = external
	txCtx := withActiveRepositories(ctx, Repositories{WorkerProjection: transaction})

	ledger.mu.Lock()
	err := ledger.refreshWorkerProjectionLocked(txCtx, actor.TenantID)
	ledger.mu.Unlock()
	if err != nil {
		t.Fatalf("refreshWorkerProjectionLocked: %v", err)
	}
	if got := transaction.loadedTenantIDs(); len(got) != 1 || got[0] != actor.TenantID {
		t.Fatalf("transaction projection tenant IDs = %v, want [%s]", got, actor.TenantID)
	}
	if got := external.loadedTenantIDs(); len(got) != 0 {
		t.Fatalf("external projection reader was called inside transaction: %v", got)
	}
}

func projectionAuditEntry(t *testing.T, tenantID string, sequence int64, previousHash, id string) domain.AuditChainEntry {
	t.Helper()
	entry := domain.AuditChainEntry{
		ID: id, TenantID: tenantID, Sequence: sequence, EntryType: "projection.tested",
		SubjectType: "projection", SubjectID: id, ActorType: "system", ActorID: "worker",
		OccurredAt: fixedNow().Add(time.Duration(sequence) * time.Second), PreviousEntryHash: previousHash,
		SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if err := RehashAuditChainEntry(&entry); err != nil {
		t.Fatalf("RehashAuditChainEntry: %v", err)
	}
	return entry
}
