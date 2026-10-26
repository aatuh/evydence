package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

const fuzzWorkerOpenAPIDocument = `{"openapi":"3.0.3","info":{"title":"API","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}}`

func TestReplayedOpenAPIPreservesYAML(t *testing.T) {
	raw := []byte("openapi: 3.0.3\ninfo:\n  title: API\n  version: '1'\npaths:\n  /health:\n    get:\n      responses:\n        '200':\n          description: OK\n")
	parsed, err := parseReplayedOpenAPIContract(t.Context(), raw)
	if err != nil || parsed.PathCount != 1 || len(parsed.Operations) != 1 {
		t.Fatalf("existing YAML replay compatibility rejected: %v", err)
	}
}

func FuzzReplayedOpenAPIContract(f *testing.F) {
	for _, version := range []string{"3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.1.0"} {
		f.Add([]byte(strings.Replace(fuzzWorkerOpenAPIDocument, "3.0.3", version, 1)))
	}
	f.Add([]byte(strings.Replace(fuzzWorkerOpenAPIDocument, `"title":"API"`, `"title":"API","\u0074itle":"ambiguous"`, 1)))
	f.Add([]byte(`{"openapi":"3.0.3","info":{"title":"API","version":"1"},"paths":{}}`))
	f.Add([]byte(`{} null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		shapeErr := jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 128, MaxArrayItems: 128, MaxStringBytes: 4096})
		if shapeErr != nil && !errors.Is(shapeErr, jsonbounds.ErrDuplicateObjectKey) {
			return
		}
		first, err := parseReplayedOpenAPIContract(t.Context(), raw)
		if err != nil {
			if err.Error() != "replayed openapi contract payload is invalid" || !reflect.DeepEqual(first, replayedOpenAPIContract{}) {
				t.Fatal("invalid replay input leaked a projection or parser error")
			}
			return
		}
		if shapeErr != nil {
			t.Fatal("ambiguous replay JSON accepted")
		}
		again, err := parseReplayedOpenAPIContract(t.Context(), raw)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("replay projection not repeatable: %v", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := parseReplayedOpenAPIContract(t.Context(), encoded)
		if err != nil || !reflect.DeepEqual(first, roundTrip) {
			t.Fatalf("JSON serialization changed replay projection: %v", err)
		}
		contract := domain.OpenAPIContract{PathCount: first.PathCount, Hash: digestBytes(raw)}
		if err := verifyReplayedOpenAPIContract(raw, first, contract); err != nil {
			t.Fatalf("matching durable contract rejected: %v", err)
		}
		contract.Hash += "tampered"
		if err := verifyReplayedOpenAPIContract(raw, first, contract); err == nil {
			t.Fatal("digest mismatch accepted")
		}
		contract.Hash, contract.PathCount = digestBytes(raw), first.PathCount+1
		if err := verifyReplayedOpenAPIContract(raw, first, contract); err == nil {
			t.Fatal("durable path-count mismatch accepted")
		}
		duplicate := append([]byte(`{"openapi":null,`), bytes.TrimSpace(raw)[1:]...)
		if _, err := parseReplayedOpenAPIContract(t.Context(), duplicate); err == nil {
			t.Fatal("duplicate OpenAPI version accepted during replay")
		}
	})
}

func TestReplayedOpenAPIRejectsDuplicateObjectKeys(t *testing.T) {
	if parsed, err := parseReplayedOpenAPIContract(t.Context(), []byte(fuzzWorkerOpenAPIDocument)); err != nil || parsed.PathCount != 1 || len(parsed.Operations) != 1 {
		t.Fatalf("positive replay OpenAPI fixture rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"root": strings.Replace(fuzzWorkerOpenAPIDocument, `"openapi":"3.0.3"`,
			`"openapi":"3.0.3","openapi":"3.0.3"`, 1),
		"escaped info key": strings.Replace(fuzzWorkerOpenAPIDocument, `"title":"API"`,
			`"title":"API","\u0074itle":"ambiguous"`, 1),
		"response status": strings.Replace(fuzzWorkerOpenAPIDocument, `"200":{"description":"OK"}`,
			`"200":{"description":"OK"},"200":{"description":"ambiguous"}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if raw == fuzzWorkerOpenAPIDocument || !json.Valid([]byte(raw)) {
				t.Fatal("duplicate-key fixture must remain valid JSON")
			}
			parsed, err := parseReplayedOpenAPIContract(t.Context(), []byte(raw))
			if err == nil || parsed.PathCount != 0 || len(parsed.Operations) != 0 {
				t.Fatalf("ambiguous replay OpenAPI JSON accepted: error=%v", err)
			}
		})
	}
}
