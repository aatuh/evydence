package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestParserProvenanceMetadataIsStableAndDoesNotMutateInput(t *testing.T) {
	input := map[string]any{"format": "spdx"}
	provenance := ParserProvenance{Name: "spdx", Version: ParserVersionSPDXJSON, SourceSchema: "spdx-2.3", NormalizedSchema: "evydence-sbom.v1", Warnings: []string{"z", "a"}, ReplayStatus: ParserReplayStatusOriginal}
	got := WithParserProvenance(input, provenance)
	if got == nil || input["parser"] != nil || got["format"] != "spdx" {
		t.Fatalf("metadata copy = %#v input = %#v", got, input)
	}
	parser, ok := got["parser"].(map[string]any)
	if !ok || parser["version"] != ParserVersionSPDXJSON || parser["replay_status"] != ParserReplayStatusOriginal {
		t.Fatalf("parser metadata = %#v", got["parser"])
	}
	warnings := parser["warnings"].([]string)
	if len(warnings) != 2 || warnings[0] != "a" || warnings[1] != "z" {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestParserProvenanceRejectsIncompleteRecords(t *testing.T) {
	if WithParserProvenance(nil, ParserProvenance{Name: "spdx", Version: "v1", SourceSchema: "spdx", NormalizedSchema: "v1", ReplayStatus: ParserReplayStatusReplayed}) == nil {
		t.Fatal("rejected derived parser provenance")
	}
	if WithParserProvenance(nil, ParserProvenance{}) != nil {
		t.Fatal("accepted incomplete parser provenance")
	}
}

func TestReplayParserEvidenceAppendsIdempotentDerivedEvidence(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[{"vulnerability":"CVE-2026-1","component":"pkg:apk/demo@1","severity":"high"}]}`)
	state := &PersistedState{Evidence: map[string]domain.EvidenceItem{"ev_source": {ID: "ev_source", TenantID: "ten_test", ReleaseID: "rel_test", Type: "vulnerability_scan", Subtype: "generic", PayloadHash: "sha256:source", PayloadRef: "object://tenants/ten_test/payloads/source", PayloadMediaType: "application/json", CreatedAt: fixedNow()}}, Chain: map[string][]domain.AuditChainEntry{}}
	request := ParserReplayRequest{TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON, ActorID: "operator_test", Now: fixedNow().Add(time.Minute)}
	first, err := ReplayParserEvidence(state, raw, request)
	if err != nil || !first.Created || first.EvidenceID == "ev_source" || len(state.Evidence) != 2 || len(state.Chain["ten_test"]) != 1 {
		t.Fatalf("first replay = %#v err=%v state=%#v", first, err, state)
	}
	derived := state.Evidence[first.EvidenceID]
	if derived.RelatedEvidenceRefs[0].ID != "ev_source" || parserReplayOf(derived.Metadata) != "ev_source" || parserReplayVersion(derived.Metadata) != ParserVersionScannerAdaptersJSON || state.Evidence["ev_source"].Metadata != nil {
		t.Fatalf("derived replay = %#v", derived)
	}
	second, err := ReplayParserEvidence(state, raw, request)
	if err != nil || second.Created || second.EvidenceID != first.EvidenceID || len(state.Evidence) != 2 || len(state.Chain["ten_test"]) != 1 {
		t.Fatalf("idempotent replay = %#v err=%v", second, err)
	}
}

func TestReplayParserEvidenceRejectsInvalidScopeAndPayload(t *testing.T) {
	request := ParserReplayRequest{TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: fixedNow()}
	state := &PersistedState{Evidence: map[string]domain.EvidenceItem{"ev_source": {ID: "ev_source", TenantID: "ten_test", Type: "vulnerability_scan"}}}
	for _, candidate := range []struct {
		state   *PersistedState
		raw     []byte
		request ParserReplayRequest
	}{
		{nil, []byte(`{}`), request},
		{state, []byte(`{}`), ParserReplayRequest{}},
		{state, []byte(`{}`), ParserReplayRequest{TenantID: "other", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: fixedNow()}},
		{state, []byte(`not-json`), request},
	} {
		if _, err := ReplayParserEvidence(candidate.state, candidate.raw, candidate.request); err == nil {
			t.Fatal("accepted invalid replay request")
		}
	}
}

func TestReplayStoredParserEvidenceVerifiesPayloadIdentityAndTenantScope(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	digest := hashBytes(raw)
	state := &PersistedState{Evidence: map[string]domain.EvidenceItem{"ev_source": {ID: "ev_source", TenantID: "ten_test", Type: "vulnerability_scan", PayloadHash: digest, PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: fixedNow()}}, Chain: map[string][]domain.AuditChainEntry{}}
	request := ParserReplayRequest{TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: fixedNow()}
	key, err := ParserReplayPayloadKey(state, request)
	if err != nil || key != "tenants/ten_test/payloads/source" {
		t.Fatalf("payload key=%q err=%v", key, err)
	}
	result, err := ReplayStoredParserEvidence(state, Object{Key: key, TenantID: "ten_test", Digest: digest, Bytes: raw}, request)
	if err != nil || !result.Created {
		t.Fatalf("stored replay=%#v err=%v", result, err)
	}
	for _, object := range []Object{
		{Key: key, TenantID: "other", Digest: digest, Bytes: raw},
		{Key: "tenants/ten_test/payloads/other", TenantID: "ten_test", Digest: digest, Bytes: raw},
		{Key: key, TenantID: "ten_test", Digest: "sha256:wrong", Bytes: raw},
		{Key: key, TenantID: "ten_test", Digest: digest, Bytes: []byte("different")},
	} {
		if _, err := ReplayStoredParserEvidence(state, object, request); err == nil {
			t.Fatalf("accepted mismatched object %#v", object)
		}
	}
	for _, invalid := range []ParserReplayRequest{{}, {TenantID: "other", EvidenceID: "ev_source"}, {TenantID: "ten_test", EvidenceID: "missing"}} {
		if _, err := ParserReplayPayloadKey(state, invalid); err == nil {
			t.Fatalf("accepted invalid replay key request %#v", invalid)
		}
	}
}

func TestReplayParserProjectionSupportsEveryVersionedParserFamily(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string) []byte {
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	tests := []struct {
		name    string
		item    domain.EvidenceItem
		raw     []byte
		version string
	}{
		{"cyclonedx", domain.EvidenceItem{Type: "sbom", Subtype: "cyclonedx"}, read("internal/app/parsers/cyclonedx/testdata/official/valid-standard-1.6.json"), ParserVersionCycloneDXJSON},
		{"spdx", domain.EvidenceItem{Type: "sbom", Subtype: "spdx"}, read("internal/app/parsers/spdx/testdata/spdx-2.3-example.json"), ParserVersionSPDXJSON},
		{"scanner", domain.EvidenceItem{Type: "vulnerability_scan"}, []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`), ParserVersionScannerAdaptersJSON},
		{"openvex", domain.EvidenceItem{Type: "vex", Subtype: "openvex"}, read("internal/app/parsers/vex/testdata/openvex/openvex-spec-minimal.json"), ParserVersionOpenVEXJSON},
		{"cyclonedx-vex", domain.EvidenceItem{Type: "vex", Subtype: "cyclonedx"}, read("internal/app/parsers/vex/testdata/cyclonedx-vex/official-vex-1.4.json"), ParserVersionCycloneDXVEXJSON},
		{"openapi", domain.EvidenceItem{Type: "openapi_contract"}, []byte(`{"openapi":"3.0.3","info":{"title":"test","version":"1"},"paths":{}}`), ParserVersionOpenAPIJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provenance, summary, err := replayParserProjection(tt.item, tt.raw, tt.version)
			if err != nil || !provenance.Valid() || provenance.ReplayStatus != ParserReplayStatusReplayed || len(summary) == 0 {
				t.Fatalf("projection = %#v summary=%#v err=%v", provenance, summary, err)
			}
		})
	}
	if _, _, err := replayParserProjection(domain.EvidenceItem{Type: "other"}, []byte("{}"), "v1"); err == nil {
		t.Fatal("accepted unsupported replay type")
	}
	if _, _, err := replayParserProjection(domain.EvidenceItem{Type: "sbom", Subtype: "spdx"}, []byte("{}"), "wrong"); err == nil {
		t.Fatal("accepted unsupported parser version")
	}
}
