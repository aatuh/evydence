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

func TestReplayParserEvidenceUsesStableIDsAcrossConcurrentSnapshots(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	initial := PersistedState{
		Evidence: map[string]domain.EvidenceItem{"ev_source": {
			ID: "ev_source", TenantID: "ten_test", ReleaseID: "rel_test", Type: "vulnerability_scan", Subtype: "generic",
			PayloadHash: "sha256:source", PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: fixedNow(),
		}},
		Chain: map[string][]domain.AuditChainEntry{},
	}
	left, err := cloneState(initial)
	if err != nil {
		t.Fatalf("clone left snapshot: %v", err)
	}
	right, err := cloneState(initial)
	if err != nil {
		t.Fatalf("clone right snapshot: %v", err)
	}
	request := ParserReplayRequest{
		TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON,
		ActorID: "operator_test", Now: fixedNow().Add(time.Minute),
	}
	first, err := ReplayParserEvidence(&left, raw, request)
	if err != nil {
		t.Fatalf("first concurrent replay: %v", err)
	}
	request.Now = request.Now.Add(time.Second)
	second, err := ReplayParserEvidence(&right, raw, request)
	if err != nil {
		t.Fatalf("second concurrent replay: %v", err)
	}
	if first.EvidenceID != second.EvidenceID {
		t.Fatalf("concurrent evidence IDs = %q and %q, want one stable ID", first.EvidenceID, second.EvidenceID)
	}
	firstEntry := left.Chain[request.TenantID][0]
	secondEntry := right.Chain[request.TenantID][0]
	if firstEntry.ID != secondEntry.ID {
		t.Fatalf("concurrent audit IDs = %q and %q, want one stable ID", firstEntry.ID, secondEntry.ID)
	}
}

func TestReplayParserEvidencePreservesEverySourceScopeCoordinate(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	request := ParserReplayRequest{
		TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON,
		ActorID: "operator_test", Now: fixedNow().Add(time.Minute),
	}
	state := &PersistedState{
		Evidence: map[string]domain.EvidenceItem{request.EvidenceID: {
			ID: request.EvidenceID, TenantID: request.TenantID, ProductID: "prod_test", ProjectID: "proj_test",
			ReleaseID: "rel_test", BuildID: "build_test", DeploymentID: "dep_test", Type: "vulnerability_scan",
			PayloadHash: "sha256:source", PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: fixedNow(),
		}},
		Chain: map[string][]domain.AuditChainEntry{},
	}
	result, err := ReplayParserEvidence(state, raw, request)
	if err != nil {
		t.Fatalf("ReplayParserEvidence: %v", err)
	}
	derived := state.Evidence[result.EvidenceID]
	source := state.Evidence[request.EvidenceID]
	if derived.ProductID != source.ProductID || derived.ProjectID != source.ProjectID || derived.ReleaseID != source.ReleaseID || derived.BuildID != source.BuildID || derived.DeploymentID != source.DeploymentID {
		t.Fatalf("derived scope = (%q,%q,%q,%q,%q), want source scope (%q,%q,%q,%q,%q)", derived.ProductID, derived.ProjectID, derived.ReleaseID, derived.BuildID, derived.DeploymentID, source.ProductID, source.ProjectID, source.ReleaseID, source.BuildID, source.DeploymentID)
	}
	if _, err := ParserReplayMutation(state, request, result); err != nil {
		t.Fatalf("ParserReplayMutation: %v", err)
	}
	for _, mutate := range []func(*domain.EvidenceItem){
		func(item *domain.EvidenceItem) { item.BuildID = "build_other" },
		func(item *domain.EvidenceItem) { item.DeploymentID = "dep_other" },
	} {
		item := state.Evidence[result.EvidenceID]
		mutate(&item)
		state.Evidence[result.EvidenceID] = item
		if _, err := ParserReplayMutation(state, request, result); err == nil {
			t.Fatal("accepted parser replay mutation with changed build/deployment scope")
		}
		state.Evidence[result.EvidenceID] = derived
	}
}

func TestParserReplayMutationContainsOnlyDerivedAppendOnlyFacts(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	request := ParserReplayRequest{TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: fixedNow()}
	state := &PersistedState{
		Products: map[string]domain.Product{"prod_unrelated": {ID: "prod_unrelated", TenantID: request.TenantID}},
		Evidence: map[string]domain.EvidenceItem{request.EvidenceID: {
			ID: request.EvidenceID, TenantID: request.TenantID, Type: "vulnerability_scan",
			PayloadHash: "sha256:source", PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: fixedNow(),
		}},
		Scans: map[string]domain.VulnerabilityScan{"scan_unrelated": {ID: "scan_unrelated", TenantID: request.TenantID}},
		Chain: map[string][]domain.AuditChainEntry{},
	}
	result, err := ReplayParserEvidence(state, raw, request)
	if err != nil {
		t.Fatalf("replay evidence: %v", err)
	}
	mutation, err := ParserReplayMutation(state, request, result)
	if err != nil {
		t.Fatalf("derive focused mutation: %v", err)
	}
	if len(mutation.Evidence) != 1 || mutation.Evidence[0].ID != result.EvidenceID || len(mutation.AuditChainEntries) != 1 || mutation.AuditChainEntries[0].SubjectID != result.EvidenceID {
		t.Fatalf("focused mutation = %#v", mutation)
	}
	if len(mutation.Products) != 0 || len(mutation.Projects) != 0 || len(mutation.Releases) != 0 || len(mutation.Artifacts) != 0 || len(mutation.EvidenceLifecycle) != 0 || len(mutation.SBOMs) != 0 || len(mutation.Scans) != 0 || len(mutation.Contracts) != 0 || len(mutation.VEXDocuments) != 0 || len(mutation.VEXImportReports) != 0 || len(mutation.BuildAttestations) != 0 || len(mutation.VulnerabilityDecisions) != 0 || len(mutation.OutboxJobs) != 0 {
		t.Fatalf("focused mutation included unrelated state: %#v", mutation)
	}

	noOp, err := ParserReplayMutation(state, request, ParserReplayResult{EvidenceID: result.EvidenceID, Parser: result.Parser})
	if err != nil || len(noOp.Evidence) != 0 || len(noOp.AuditChainEntries) != 0 {
		t.Fatalf("idempotent no-op mutation = %#v err=%v", noOp, err)
	}
}

func TestParserReplayMutationRejectsInvalidScopeAndLinkage(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	request := ParserReplayRequest{TenantID: "ten_test", EvidenceID: "ev_source", ParserVersion: ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: fixedNow()}
	newReplay := func(t *testing.T) (*PersistedState, ParserReplayResult) {
		t.Helper()
		state := &PersistedState{Evidence: map[string]domain.EvidenceItem{request.EvidenceID: {
			ID: request.EvidenceID, TenantID: request.TenantID, Type: "vulnerability_scan",
			PayloadHash: "sha256:source", PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: fixedNow(),
		}}, Chain: map[string][]domain.AuditChainEntry{}}
		result, err := ReplayParserEvidence(state, raw, request)
		if err != nil {
			t.Fatalf("replay evidence: %v", err)
		}
		return state, result
	}

	tests := []struct {
		name   string
		mutate func(*PersistedState, ParserReplayResult)
	}{
		{"derived tenant", func(state *PersistedState, result ParserReplayResult) {
			item := state.Evidence[result.EvidenceID]
			item.TenantID = "ten_other"
			state.Evidence[item.ID] = item
		}},
		{"derived type", func(state *PersistedState, result ParserReplayResult) {
			item := state.Evidence[result.EvidenceID]
			item.Type = "note"
			state.Evidence[item.ID] = item
		}},
		{"source relationship", func(state *PersistedState, result ParserReplayResult) {
			item := state.Evidence[result.EvidenceID]
			item.RelatedEvidenceRefs = nil
			state.Evidence[item.ID] = item
		}},
		{"audit subject", func(state *PersistedState, _ ParserReplayResult) {
			entry := state.Chain[request.TenantID][0]
			entry.SubjectID = request.EvidenceID
			state.Chain[request.TenantID][0] = entry
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, result := newReplay(t)
			tt.mutate(state, result)
			if _, err := ParserReplayMutation(state, request, result); err == nil {
				t.Fatal("accepted malformed replay mutation")
			}
		})
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
