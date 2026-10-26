package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

type replayFuzzCase struct {
	kind                           uint8
	evidenceType, subtype, version string
	file                           string
	raw                            []byte
}

func replayFuzzJSON(t testing.TB, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func replayFuzzSnapshot(t testing.TB, state *PersistedState) string {
	t.Helper()
	// The production preview API needs these two bounded tables. No Ledger,
	// database, unrelated tenant state or global application fixture is built.
	return replayFuzzJSON(t, struct {
		Evidence map[string]domain.EvidenceItem
		Chain    map[string][]domain.AuditChainEntry
	}{state.Evidence, state.Chain})
}

func replayFuzzFixture(t testing.TB, c replayFuzzCase, raw []byte) (*PersistedState, Object, ParserReplayRequest) {
	t.Helper()
	now := time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)
	digest := hashBytes(raw)
	_, key, err := CanonicalObjectPayloadKeys("tenant", digest)
	if err != nil {
		t.Fatal(err)
	}
	item := domain.EvidenceItem{
		ID: "source", TenantID: "tenant", ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment",
		Type: c.evidenceType, Subtype: c.subtype, Title: "Synthetic replay source", SourceSystem: "synthetic", UploadedBy: "collector",
		ObservedAt: now, CreatedAt: now, EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadRef: "object://" + key, PayloadHash: digest, PayloadMediaType: "application/json", PayloadSize: int64(len(raw)),
		Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "L2", VerificationStatus: "recorded",
	}
	item = withEvidenceCanonicalOriginRefs(item)
	item.CanonicalHash, err = canonicalHash(item)
	if err != nil {
		t.Fatal(err)
	}
	state := &PersistedState{Evidence: map[string]domain.EvidenceItem{item.ID: item}, Chain: map[string][]domain.AuditChainEntry{}}
	object := Object{TenantID: item.TenantID, Key: key, Digest: digest, MediaType: item.PayloadMediaType, Bytes: append([]byte(nil), raw...)}
	request := ParserReplayRequest{TenantID: item.TenantID, EvidenceID: item.ID, ParserVersion: c.version, ActorID: "operator", Now: now.Add(time.Minute)}
	return state, object, request
}

func replayFuzzCheckSuccess(t *testing.T, c replayFuzzCase, raw []byte, mode uint8) bool {
	t.Helper()
	state, object, request := replayFuzzFixture(t, c, raw)
	source := state.Evidence[request.EvidenceID]
	sourceBefore := replayFuzzJSON(t, source)
	before := replayFuzzSnapshot(t, state)
	result, err := ReplayStoredParserEvidence(state, object, request)
	if err != nil {
		if !errors.Is(err, ErrValidation) || replayFuzzSnapshot(t, state) != before || result.EvidenceID != "" {
			t.Fatal("invalid replay input mutated preview state or leaked a result")
		}
		return false
	}
	if !result.Created || result.EvidenceID == source.ID || len(state.Evidence) != 2 || len(state.Chain[request.TenantID]) != 1 || replayFuzzJSON(t, state.Evidence[source.ID]) != sourceBefore || !bytes.Equal(object.Bytes, raw) {
		t.Fatal("replay did not append exactly one derived record and audit entry")
	}
	mutation, err := ParserReplayMutation(state, request, result)
	if err != nil || len(mutation.Evidence) != 1 || len(mutation.AuditChainEntries) != 1 || mutation.Evidence[0].ID != result.EvidenceID {
		t.Fatal("valid replay failed append-only mutation validation", err)
	}
	item, entry := mutation.Evidence[0], mutation.AuditChainEntries[0]
	if err := ValidateParserNormalizationRecord(request.TenantID, item, source, entry); err != nil {
		t.Fatal("valid durable normalization marker rejected", err)
	}
	created := replayFuzzSnapshot(t, state)
	again, err := ReplayStoredParserEvidence(state, object, request)
	if err != nil || again.Created || again.EvidenceID != result.EvidenceID || !reflect.DeepEqual(result.Parser, again.Parser) || !reflect.DeepEqual(result.Summary, again.Summary) || replayFuzzSnapshot(t, state) != created {
		t.Fatal("repeated replay changed identity, interpretation or immutable facts")
	}
	noOp, err := ParserReplayMutation(state, request, again)
	if err != nil || !reflect.DeepEqual(noOp, ReleaseLedgerMutation{}) {
		t.Fatal("idempotent replay emitted another persistence mutation")
	}
	copyState, copyObject, copyRequest := replayFuzzFixture(t, c, raw)
	repeated, err := ReplayStoredParserEvidence(copyState, copyObject, copyRequest)
	if err != nil || !reflect.DeepEqual(result, repeated) || replayFuzzSnapshot(t, copyState) != created {
		t.Fatal("independent bounded previews did not produce the same replay")
	}
	// A matching checksum alone cannot confer tenant/relationship authority.
	// Exercise the native record verifier separately from mutation assembly.
	changedItem, changedSource, changedEntry := item, source, entry
	switch mode % 8 {
	case 0:
		changedItem.TenantID = "foreign"
		changedItem.CanonicalHash, err = canonicalHash(changedItem)
		if err != nil {
			t.Fatal(err)
		}
	case 1:
		changedItem.PayloadHash = "sha256:" + strings.Repeat("0", 64)
	case 2:
		changedItem.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "evidence_item", ID: "foreign", Relationship: "replayed_from"}}
	case 3:
		changedEntry.ActorID = "other"
	case 4:
		changedEntry.EntryHash += "changed"
	case 5:
		changedSource.TenantID = "foreign"
	case 6:
		changedItem.Title += "changed"
	case 7:
		changedItem.SignatureRefs = []string{"unexpected"}
	}
	if err := ValidateParserNormalizationRecord(request.TenantID, changedItem, changedSource, changedEntry); err == nil {
		t.Fatal("changed native normalization record acquired authority")
	}
	return true
}

func FuzzStoredParserReplay(f *testing.F) {
	cases := []replayFuzzCase{
		{kind: 0, evidenceType: "sbom", subtype: "cyclonedx", version: ParserVersionCycloneDXJSON, file: "parsers/cyclonedx/testdata/official/valid-dependency-1.6.json"},
		{kind: 1, evidenceType: "sbom", subtype: "spdx", version: ParserVersionSPDXJSON, file: "parsers/spdx/testdata/spdx-2.3-example.json"},
		{kind: 2, evidenceType: "vulnerability_scan", subtype: "generic", version: ParserVersionScannerAdaptersJSON, file: "parsers/scanners/testdata/generic.json"},
		{kind: 3, evidenceType: "vex", subtype: "openvex", version: ParserVersionOpenVEXJSON, file: "parsers/vex/testdata/openvex/openvex-spec-minimal.json"},
		{kind: 4, evidenceType: "vex", subtype: "cyclonedx", version: ParserVersionCycloneDXVEXJSON, file: "parsers/vex/testdata/cyclonedx-vex/official-vex-1.4.json"},
		{kind: 5, evidenceType: "openapi_contract", version: ParserVersionOpenAPIJSON, raw: []byte(focusedOpenAPIDocument)},
		{kind: 6, evidenceType: "vulnerability_scan", subtype: "generic", version: ParserVersionGenericVulnerabilityJSON, file: "parsers/scanners/testdata/generic.json"},
	}
	for i := range cases {
		c := &cases[i]
		if c.file != "" {
			var err error
			c.raw, err = os.ReadFile(c.file)
			if err != nil {
				f.Fatal(err)
			}
		}
		for mode := uint8(0); mode < 8; mode++ {
			f.Add(c.raw, c.kind, mode)
		}
	}
	f.Add([]byte(strings.Replace(focusedOpenAPIDocument, `"openapi":"3.0.3"`, `"openapi":"3.0.3","openapi":"3.0.3"`, 1)), uint8(5), uint8(0))
	f.Add([]byte(strings.Replace(focusedOpenAPIDocument, `"title":"API"`, `"title":"API","\u0074itle":"ambiguous"`, 1)), uint8(5), uint8(1))
	f.Add([]byte(strings.Replace(focusedOpenAPIDocument, `"200":{"description":"OK"}`, `"200":{"description":"OK"},"200":{"description":"ambiguous"}`, 1)), uint8(5), uint8(2))
	f.Add([]byte(`{}`), uint8(0), uint8(0))
	f.Add([]byte(`null`), uint8(5), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, family, mode uint8) {
		if len(raw) > 64<<10 {
			return
		}
		shapeErr := jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 128, MaxArrayItems: 128, MaxStringBytes: 4096})
		if shapeErr != nil && !errors.Is(shapeErr, jsonbounds.ErrDuplicateObjectKey) {
			return
		}
		c := cases[int(family)%len(cases)]
		replayFuzzSourceProperties(t, c, raw, mode, false)
		replayFuzzSourceProperties(t, c, c.raw, mode, true)
		if accepted := replayFuzzCheckSuccess(t, c, raw, mode); shapeErr != nil && accepted {
			t.Fatal("ambiguous JSON acquired a stored replay interpretation")
		}
		// Independently require a known-good projection for every selected
		// family, even when the generated input is invalid.
		positiveState, positiveObject, positiveRequest := replayFuzzFixture(t, c, c.raw)
		positive, err := ReplayStoredParserEvidence(positiveState, positiveObject, positiveRequest)
		if err != nil || !positive.Created || positive.Parser.Version != c.version {
			t.Fatalf("known replay fixture rejected: %v", err)
		}
		changed, object, request := replayFuzzFixture(t, c, c.raw)
		want := ErrValidation
		switch mode % 8 {
		case 0:
			object.TenantID = "foreign"
		case 1:
			object.Key += "changed"
		case 2:
			object.Digest += "changed"
		case 3:
			object.Bytes[0] ^= 1
		case 4:
			request.TenantID, want = "foreign", ErrNotFound
		case 5:
			item := changed.Evidence[request.EvidenceID]
			item.TenantID = "foreign"
			changed.Evidence[request.EvidenceID], want = item, ErrNotFound
		case 6:
			request.ParserVersion = "unsupported"
		case 7:
			item := changed.Evidence[request.EvidenceID]
			item.PayloadRef = "object://tenants/foreign/payload"
			changed.Evidence[request.EvidenceID] = item
		}
		before := replayFuzzSnapshot(t, changed)
		result, err := ReplayStoredParserEvidence(changed, object, request)
		if !errors.Is(err, want) || result.EvidenceID != "" || replayFuzzSnapshot(t, changed) != before {
			t.Fatal("unbound or unauthorized replay changed state or produced derived facts")
		}
	})
}
