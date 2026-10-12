package httpapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSecurityDocumentContractMatchesAcceptedShapesAndReplayPrivacy(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, spec["components"])["schemas"])
	paths := asStringAnyMap(t, spec["paths"])
	for _, tc := range []struct {
		path, schema     string
		fields, required []string
	}{
		{"/v1/security-scans", "UploadSecurityScanRequest", []string{"artifact_id", "category", "format", "payload", "product_id", "release_id", "scanner", "target_ref"}, []string{"category", "payload", "scanner", "target_ref"}},
		{"/v1/api-security-scans", "UploadAPISecurityScanRequest", []string{"artifact_id", "format", "payload", "product_id", "release_id", "scanner", "target_ref"}, []string{"payload", "scanner", "target_ref"}},
		{"/v1/security-documents", "UploadManualSecurityDocumentRequest", []string{"document_type", "media_type", "payload", "product_id", "release_id", "sensitivity", "title"}, []string{"document_type", "payload", "sensitivity", "title"}},
	} {
		op := asStringAnyMap(t, asStringAnyMap(t, paths[tc.path])["post"])
		body := asStringAnyMap(t, op["requestBody"])
		media := asStringAnyMap(t, asStringAnyMap(t, body["content"])["application/json"])
		if asStringAnyMap(t, media["schema"])["$ref"] != "#/components/schemas/"+tc.schema {
			t.Fatalf("%s advertises the wrong request schema", tc.path)
		}
		definition := asStringAnyMap(t, schemas[tc.schema])
		properties := asStringAnyMap(t, definition["properties"])
		var fields, required []string
		for name := range properties {
			fields = append(fields, name)
		}
		for _, name := range definition["required"].([]any) {
			required = append(required, name.(string))
		}
		sort.Strings(fields)
		sort.Strings(required)
		if !reflect.DeepEqual(fields, tc.fields) || !reflect.DeepEqual(required, tc.required) {
			t.Fatal("unsupported or missing request fields", tc.schema, fields, required)
		}
		if _, present := properties["format"]; present && asStringAnyMap(t, properties["format"])["default"] != "generic" {
			t.Fatal("format default missing")
		}
		description := op["description"].(string)
		for _, detail := range []string{"PostgreSQL", "security:write", "64 KiB", "current", "transaction", "Ledger", "replay", "payload_ref"} {
			if !strings.Contains(description, detail) {
				t.Fatal("focused security upload contract missing", tc.path, detail)
			}
		}
	}
	for _, tc := range []struct {
		schema, field string
		values        []any
	}{
		{"UploadSecurityScanRequest", "category", []any{"sast", "dast", "secret_scan", "license_scan", "api_security"}},
		{"UploadManualSecurityDocumentRequest", "document_type", []any{"threat_model", "security_review", "pen_test_report"}},
	} {
		properties := asStringAnyMap(t, asStringAnyMap(t, schemas[tc.schema])["properties"])
		if got := asStringAnyMap(t, properties[tc.field])["enum"]; !reflect.DeepEqual(got, tc.values) {
			t.Fatal("document enum differs from parser", tc.schema, got)
		}
	}
	manual := asStringAnyMap(t, asStringAnyMap(t, schemas["UploadManualSecurityDocumentRequest"])["properties"])
	payload := asStringAnyMap(t, manual["payload"])
	var types []string
	for _, entry := range payload["oneOf"].([]any) {
		types = append(types, asStringAnyMap(t, entry)["type"].(string))
	}
	sort.Strings(types)
	if !reflect.DeepEqual(types, []string{"array", "boolean", "number", "object", "string"}) {
		t.Fatal("manual opaque JSON values changed", types)
	}
	for _, name := range []string{"SecurityScan", "ManualSecurityDocument"} {
		properties := asStringAnyMap(t, asStringAnyMap(t, schemas[name])["properties"])
		if !strings.Contains(asStringAnyMap(t, properties["payload_ref"])["description"].(string), "omitted on idempotent replay") {
			t.Fatal("replay reference privacy missing", name)
		}
	}
}
