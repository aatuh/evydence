package main

import (
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// Exercise the production processor, rather than just an isolated reader: its
// captured budget must reach every parser after digest/tenant verification.
func TestConfiguredWorkerParserBudgetReachesStructuredReplay(t *testing.T) {
	for _, tc := range []struct{ name, kind, version, document, format string }{
		{"cyclonedx-sbom", "parse_sbom", app.ParserVersionCycloneDXJSON, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"component"}]}`, ""},
		{"spdx-sbom", "parse_sbom", app.ParserVersionSPDXJSON, `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"document","dataLicense":"CC0-1.0","documentNamespace":"https://example.test/spdx","creationInfo":{"creators":["Tool: fixture"],"created":"2026-01-01T00:00:00Z"},"packages":[{"name":"component","SPDXID":"SPDXRef-component","downloadLocation":"NOASSERTION"}]}`, ""},
		{"scanner", "parse_vulnerability_scan", app.ParserVersionScannerAdaptersJSON, `{"scanner":"generic","target_ref":"artifact","release_id":"release","findings":[]}`, ""},
		{"openvex", "parse_vex", app.ParserVersionOpenVEXJSON, `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:fixture","author":"fixture","timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/component"}],"status":"fixed"}]}`, "openvex"},
		{"cyclonedx-vex", "parse_vex", app.ParserVersionCycloneDXVEXJSON, `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved"}}]}`, "cyclonedx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Whitespace increases only the byte budget, preserving depth, string,
			// item-count and schema limits. This is just above the former fixed cap.
			const legacyBytes = 20 << 20
			raw := make([]byte, legacyBytes+1+len(tc.document))
			for index := range raw[:legacyBytes+1] {
				raw[index] = ' '
			}
			copy(raw[legacyBytes+1:], tc.document)
			digest := digestBytes(raw)
			for _, within := range []bool{false, true} {
				limit := int64(len(raw)) - 1
				if within {
					limit = int64(len(raw)) + 1
				}
				snapshot := app.PersistedState{
					SBOMs:        map[string]domain.SBOM{"subject": {ID: "subject", TenantID: "tenant"}},
					Scans:        map[string]domain.VulnerabilityScan{"subject": {ID: "subject", TenantID: "tenant"}},
					VEXDocuments: map[string]domain.VEXDocument{"subject": {ID: "subject", TenantID: "tenant", Format: tc.format}},
				}
				store := &nativeProcessorStoreFake{state: snapshot}
				reader := &nativeBoundedReadFake{object: app.Object{TenantID: "tenant", Key: "tenants/tenant/raw/payload", Digest: digest, Bytes: raw}}
				processor, err := newNativeJobProcessor(store, &configuredLimitObjects{reader: reader}, limit)
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", "1")
				job := postgres.ClaimedJob{ID: "job", LeaseToken: "lease", Kind: tc.kind, TenantID: "tenant", SubjectID: "subject", Payload: map[string]any{"payload_ref": "object://tenants/tenant/raw/payload", "payload_hash": digest, "parser_version": tc.version}}
				err = processor.Process(t.Context(), job)
				if reader.limit != limit || reader.bounded != 1 || reader.gets != 0 {
					t.Fatal("processor changed its captured read budget")
				}
				if within {
					if err != nil || store.loads != 1 || store.writes != 1 {
						t.Fatalf("within-budget replay failed before its claim-fenced projection: loads=%d writes=%d error=%v", store.loads, store.writes, err)
					}
				} else {
					expectedLoads := 0
					if tc.kind == "parse_vex" {
						expectedLoads = 1
					} // Existing failure-report lookup.
					if err == nil || !strings.Contains(err.Error(), "worker size limit") || store.loads != expectedLoads || store.writes != 0 {
						t.Fatal("over-budget replay reached a projection or changed failure-report behavior")
					}
				}
			}
		})
	}
}

func TestNormalizedVEXDecisionRequestUsesCapturedByteBudget(t *testing.T) {
	job := postgres.ClaimedJob{Payload: map[string]any{
		"decision_request_schema": "vex-decision-request.v1.0.0",
		"decision_statements":     []any{map[string]any{"statement_index": float64(1), "vulnerability": "CVE-1", "products": []any{"pkg:oci/component"}, "status": "fixed", "justification": "fixed", "impact_statement": "patched", "action_statement": "ship"}},
	}}
	vex := domain.VEXDocument{Format: "openvex", Author: "fixture", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}}
	t.Setenv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", "PRIVATE_AMBIENT")
	if _, ok, err := normalizedVEXDecisionRequest(job, vex, 1); ok || err == nil || !strings.Contains(err.Error(), "normalized vex decision request is invalid") {
		t.Fatal("normalized decision inputs bypassed the configured byte budget")
	}
	if _, ok, err := normalizedVEXDecisionRequest(job, vex, 4096); !ok || err != nil {
		t.Fatal("valid normalized decision input reread ambient configuration or failed its captured budget", err)
	}
}
