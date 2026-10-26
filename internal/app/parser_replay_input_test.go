package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestParserReplayOpenAPIPreservesJSONAndYAML(t *testing.T) {
	for name, raw := range map[string]string{
		"JSON": focusedOpenAPIDocument,
		"YAML": "openapi: 3.0.3\ninfo:\n  title: API\n  version: '1'\npaths:\n  /health:\n    get:\n      responses:\n        '200':\n          description: OK\n",
	} {
		t.Run(name, func(t *testing.T) {
			provenance, summary, err := replayParserProjection(domain.EvidenceItem{Type: "openapi_contract"}, []byte(raw), ParserVersionOpenAPIJSON)
			if err != nil || provenance.Name != "openapi" || provenance.Version != ParserVersionOpenAPIJSON || summary["path_count"] != 1 {
				t.Fatalf("existing replay input rejected: %v", err)
			}
		})
	}
}

func TestParserReplayOpenAPIRejectsDuplicateObjectKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"root":         strings.Replace(focusedOpenAPIDocument, `"openapi":"3.0.3"`, `"openapi":"3.0.3","openapi":"3.0.3"`, 1),
		"escaped info": strings.Replace(focusedOpenAPIDocument, `"title":"API"`, `"title":"API","\u0074itle":"ambiguous"`, 1),
		"response":     strings.Replace(focusedOpenAPIDocument, `"200":{"description":"OK"}`, `"200":{"description":"OK"},"200":{"description":"ambiguous"}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if raw == focusedOpenAPIDocument || !json.Valid([]byte(raw)) {
				t.Fatal("duplicate-key vector must remain valid JSON")
			}
			provenance, summary, err := replayParserProjection(domain.EvidenceItem{Type: "openapi_contract"}, []byte(raw), ParserVersionOpenAPIJSON)
			if !errors.Is(err, ErrValidation) || provenance.Name != "" || summary != nil {
				t.Fatalf("ambiguous OpenAPI replay accepted: %v", err)
			}
		})
	}
}

func TestParserNormalizationRejectsForeignRehashedRecord(t *testing.T) {
	c := replayFuzzCase{evidenceType: "openapi_contract", version: ParserVersionOpenAPIJSON}
	state, object, request := replayFuzzFixture(t, c, []byte(focusedOpenAPIDocument))
	result, err := ReplayStoredParserEvidence(state, object, request)
	if err != nil {
		t.Fatal(err)
	}
	item := state.Evidence[result.EvidenceID]
	source, entry := state.Evidence[request.EvidenceID], state.Chain[request.TenantID][0]
	if err := ValidateParserNormalizationRecord(request.TenantID, item, source, entry); err != nil {
		t.Fatal("positive native record rejected", err)
	}
	item.TenantID = "foreign"
	item.CanonicalHash, err = canonicalHash(item)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateParserNormalizationRecord(request.TenantID, item, source, entry); err == nil {
		t.Fatal("self-consistent foreign record accepted by native ownership verifier")
	}
}
