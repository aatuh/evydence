package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

func TestOpenAPIContractPayloadParserPreservesYAML(t *testing.T) {
	raw := []byte("openapi: 3.0.3\ninfo:\n  title: API\n  version: '1'\npaths:\n  /health:\n    get:\n      responses:\n        '200':\n          description: OK\n")
	parsed, err := (OpenAPIContractPayloadParser{}).ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource(raw))
	if err != nil || parsed.PathCount != 1 || len(parsed.Operations) != 1 {
		t.Fatalf("existing YAML compatibility rejected: %v", err)
	}
}

func FuzzOpenAPIContract(f *testing.F) {
	for _, version := range []string{"3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.1.0"} {
		f.Add([]byte(strings.Replace(focusedOpenAPIDocument, "3.0.3", version, 1)))
	}
	for _, raw := range []string{
		strings.Replace(focusedOpenAPIDocument, `"title":"API"`, `"title":"API","\u0074itle":"ambiguous"`, 1),
		strings.Replace(focusedOpenAPIDocument, `"openapi":"3.0.3"`, `"openapi":"3.0.3","openapi":"3.0.3"`, 1),
		strings.Replace(focusedOpenAPIDocument, `"200":{"description":"OK"}`, `"200":{"description":"OK"},"200":{"description":"ambiguous"}`, 1),
		`{"openapi":"3.0.3","info":{"title":"API","version":"1"},"paths":{}}`,
		`{} null`, `{"openapi":"9.9.9"}`, `null`,
	} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		// These are workload bounds for this harness, not a new production
		// acceptance policy. Duplicate-key seeds still reach the real owner.
		shapeErr := jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 128, MaxArrayItems: 128, MaxStringBytes: 4096})
		if shapeErr != nil && !errors.Is(shapeErr, jsonbounds.ErrDuplicateObjectKey) {
			return
		}
		parser := OpenAPIContractPayloadParser{}
		first, err := parser.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource(raw))
		if err != nil {
			if !errors.Is(err, evidenceapp.ErrValidation) || !reflect.DeepEqual(first, evidenceapp.ParsedOpenAPIContract{}) {
				t.Fatal("invalid input leaked a projection or parser error")
			}
			return
		}
		if shapeErr != nil {
			t.Fatal("ambiguous JSON accepted")
		}
		again, err := parser.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource(raw))
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("OpenAPI projection not repeatable: %v", err)
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
		roundTrip, err := parser.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource(encoded))
		if err != nil || !reflect.DeepEqual(first, roundTrip) {
			t.Fatalf("JSON serialization changed OpenAPI projection: %v", err)
		}
		if first.ParserVersion != ParserVersionOpenAPIJSON || !strings.HasPrefix(first.SourceSchema, "openapi-") {
			t.Fatal("parser provenance missing")
		}
		duplicate := append([]byte(`{"openapi":null,`), bytes.TrimSpace(raw)[1:]...)
		if _, err := parser.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource(duplicate)); !errors.Is(err, evidenceapp.ErrValidation) {
			t.Fatal("duplicate OpenAPI version accepted")
		}
		for _, tamper := range []string{"digest", "size"} {
			source := evidenceapp.BytesPayloadSource(raw)
			if tamper == "size" {
				source.Size++
			} else if strings.HasSuffix(source.Digest, "0") {
				source.Digest = source.Digest[:len(source.Digest)-1] + "1"
			} else {
				source.Digest = source.Digest[:len(source.Digest)-1] + "0"
			}
			if _, err := parser.ParseOpenAPIContract(t.Context(), source); !errors.Is(err, evidenceapp.ErrValidation) {
				t.Fatalf("unbound %s accepted", tamper)
			}
		}
	})
}

func TestOpenAPIContractPayloadParserRejectsDuplicateObjectKeys(t *testing.T) {
	parser := OpenAPIContractPayloadParser{}
	if _, err := parser.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource([]byte(focusedOpenAPIDocument))); err != nil {
		t.Fatalf("positive OpenAPI fixture rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"root": strings.Replace(focusedOpenAPIDocument, `"openapi":"3.0.3"`,
			`"openapi":"3.0.3","openapi":"3.0.3"`, 1),
		"escaped info key": strings.Replace(focusedOpenAPIDocument, `"title":"API"`,
			`"title":"API","\u0074itle":"ambiguous"`, 1),
		"response status": strings.Replace(focusedOpenAPIDocument, `"200":{"description":"OK"}`,
			`"200":{"description":"OK"},"200":{"description":"ambiguous"}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if raw == focusedOpenAPIDocument || !json.Valid([]byte(raw)) {
				t.Fatal("duplicate-key fixture must remain valid JSON")
			}
			parsed, err := parser.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource([]byte(raw)))
			if !errors.Is(err, evidenceapp.ErrValidation) || parsed.ParserVersion != "" || len(parsed.Operations) != 0 {
				t.Fatalf("ambiguous OpenAPI JSON accepted: error=%v", err)
			}
		})
	}
}
