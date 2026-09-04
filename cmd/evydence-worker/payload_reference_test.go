package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestProcessJobWithObjectsRejectsMissingPayloadReferenceForAcceptedParserProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	const privateReference = "object://tenants/ten_test/payloads/private-evidence-name"

	tests := []struct {
		name  string
		job   postgres.ClaimedJob
		state app.PersistedState
	}{
		{
			name: "accepted SBOM",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_sbom", SubjectID: "sbom_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionCycloneDXJSON,
			}},
			state: app.PersistedState{
				Evidence: map[string]domain.EvidenceItem{"ev_sbom": {ID: "ev_sbom", TenantID: "ten_test", PayloadRef: privateReference, PayloadHash: digest}},
				SBOMs:    map[string]domain.SBOM{"sbom_test": {ID: "sbom_test", TenantID: "ten_test", EvidenceID: "ev_sbom", Format: "cyclonedx", CreatedAt: now}},
			},
		},
		{
			name: "accepted vulnerability scan",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_vulnerability_scan", SubjectID: "scan_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionScannerAdaptersJSON,
			}},
			state: app.PersistedState{
				Evidence: map[string]domain.EvidenceItem{"ev_scan": {ID: "ev_scan", TenantID: "ten_test", PayloadRef: privateReference, PayloadHash: digest}},
				Scans:    map[string]domain.VulnerabilityScan{"scan_test": {ID: "scan_test", TenantID: "ten_test", EvidenceID: "ev_scan", ReleaseID: "rel_test", CreatedAt: now}},
			},
		},
		{
			name: "accepted OpenAPI contract",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_openapi_contract", SubjectID: "contract_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionOpenAPIJSON,
			}},
			state: app.PersistedState{
				Evidence: map[string]domain.EvidenceItem{"ev_contract": {ID: "ev_contract", TenantID: "ten_test", PayloadRef: privateReference, PayloadHash: digest}},
				Contracts: map[string]domain.OpenAPIContract{"contract_test": {
					ID: "contract_test", TenantID: "ten_test", EvidenceID: "ev_contract", ProductID: "prod_test", Version: "v1", Hash: digest, CreatedAt: now,
				}},
			},
		},
		{
			name: "accepted build attestation",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "verify_attestation", SubjectID: "attestation_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionDSSEInTotoJSON,
			}},
			state: app.PersistedState{BuildAttestations: map[string]domain.BuildAttestation{"attestation_test": {
				ID: "attestation_test", TenantID: "ten_test", EvidenceID: "ev_attestation", PayloadRef: privateReference,
				PayloadHash: digest, VerificationStatus: "accepted", CreatedAt: now,
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := processJobWithObjects(context.Background(), fakeStateLoader{state: tt.state, ok: true}, fakeObjectGetter{}, tt.job)
			if err == nil || !strings.Contains(err.Error(), "parser payload reference is missing") {
				t.Fatalf("error = %v, want missing parser payload reference", err)
			}
			if strings.Contains(err.Error(), privateReference) || strings.Contains(err.Error(), tt.job.SubjectID) {
				t.Fatalf("error leaked payload reference or subject identity: %v", err)
			}
			failure := classifyWorkerFailure(err)
			if failure.Class != postgres.JobFailurePoisoned || failure.Code != "payload_invariant_failed" {
				t.Fatalf("failure classification = %#v", failure)
			}
		})
	}
}

func TestProcessJobWithObjectsAcceptsLegacyParsedProjectionWithoutPayloadReference(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("b", 64)

	tests := []struct {
		name  string
		job   postgres.ClaimedJob
		state app.PersistedState
	}{
		{
			name: "parsed empty SBOM",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_sbom", SubjectID: "sbom_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionCycloneDXJSON,
			}},
			state: app.PersistedState{SBOMs: map[string]domain.SBOM{"sbom_test": {
				ID: "sbom_test", TenantID: "ten_test", Format: "cyclonedx", SpecVersion: "1.6", Components: []domain.SBOMComponent{}, CreatedAt: now,
			}}},
		},
		{
			name: "parsed empty vulnerability scan",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_vulnerability_scan", SubjectID: "scan_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionScannerAdaptersJSON,
			}},
			state: app.PersistedState{Scans: map[string]domain.VulnerabilityScan{"scan_test": {
				ID: "scan_test", TenantID: "ten_test", ReleaseID: "rel_test", Scanner: "generic", Adapter: "generic",
				AdapterVersion: app.ParserVersionScannerAdaptersJSON, SourceSchema: "generic-vulnerability-scan-json.v1",
				TargetRef: "pkg:oci/api", Summary: map[string]int{}, Findings: []domain.VulnerabilityFinding{}, CreatedAt: now,
			}}},
		},
		{
			name: "parsed OpenAPI contract without paths",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_openapi_contract", SubjectID: "contract_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionOpenAPIJSON,
			}},
			state: app.PersistedState{Contracts: map[string]domain.OpenAPIContract{"contract_test": {
				ID: "contract_test", TenantID: "ten_test", ProductID: "prod_test", Version: "v1", Hash: digest,
				Operations: []domain.OpenAPIOperation{}, CreatedAt: now,
			}}},
		},
		{
			name: "parsed build attestation",
			job: postgres.ClaimedJob{TenantID: "ten_test", Kind: "verify_attestation", SubjectID: "attestation_test", Payload: map[string]any{
				"payload_hash": digest, "parser_version": app.ParserVersionDSSEInTotoJSON,
			}},
			state: app.PersistedState{BuildAttestations: map[string]domain.BuildAttestation{"attestation_test": {
				ID: "attestation_test", TenantID: "ten_test", PayloadHash: digest, PayloadType: "application/vnd.in-toto+json",
				PredicateType: "https://slsa.dev/provenance/v1", SubjectDigests: []string{digest}, SignatureCount: 1,
				VerificationStatus: "structurally_valid", CreatedAt: now,
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := processJobWithObjects(context.Background(), fakeStateLoader{state: tt.state, ok: true}, fakeObjectGetter{}, tt.job); err != nil {
				t.Fatalf("process legacy parsed projection: %v", err)
			}
		})
	}
}

func TestMissingPayloadReferenceGuardDoesNotInspectForeignTenantProjection(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("c", 64)
	tests := []struct {
		name    string
		job     postgres.ClaimedJob
		state   app.PersistedState
		wantErr string
	}{
		{
			name:    "SBOM",
			job:     postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_sbom", SubjectID: "subject", Payload: map[string]any{"payload_hash": digest}},
			state:   app.PersistedState{SBOMs: map[string]domain.SBOM{"subject": {ID: "subject", TenantID: "ten_foreign"}}},
			wantErr: "parsed sbom is not available",
		},
		{
			name:    "vulnerability scan",
			job:     postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_vulnerability_scan", SubjectID: "subject", Payload: map[string]any{"payload_hash": digest}},
			state:   app.PersistedState{Scans: map[string]domain.VulnerabilityScan{"subject": {ID: "subject", TenantID: "ten_foreign"}}},
			wantErr: "parsed vulnerability scan is not available",
		},
		{
			name:    "OpenAPI contract",
			job:     postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_openapi_contract", SubjectID: "subject", Payload: map[string]any{"payload_hash": digest}},
			state:   app.PersistedState{Contracts: map[string]domain.OpenAPIContract{"subject": {ID: "subject", TenantID: "ten_foreign"}}},
			wantErr: "parsed openapi contract is not available",
		},
		{
			name:    "build attestation",
			job:     postgres.ClaimedJob{TenantID: "ten_test", Kind: "verify_attestation", SubjectID: "subject", Payload: map[string]any{"payload_hash": digest}},
			state:   app.PersistedState{BuildAttestations: map[string]domain.BuildAttestation{"subject": {ID: "subject", TenantID: "ten_foreign", VerificationStatus: "accepted"}}},
			wantErr: "build attestation is not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := processJobWithObjects(context.Background(), fakeStateLoader{state: tt.state, ok: true}, fakeObjectGetter{}, tt.job)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want tenant-scoped durable-state rejection", err)
			}
			if strings.Contains(err.Error(), "payload reference") || strings.Contains(err.Error(), tt.job.SubjectID) {
				t.Fatalf("foreign projection state leaked through error: %v", err)
			}
		})
	}
}
