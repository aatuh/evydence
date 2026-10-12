package httpapi

import (
	"encoding/json"
	"testing"
)

func TestCandidateResponseSchemaDefinesReturnedRevisionAndFields(t *testing.T) {
	server, secret := catalogQueryTestServer(t)
	p := postJSON(t, server, secret, "/v1/products", "candidate-schema-product", map[string]any{"name": "Product", "slug": "product"}, 201)
	r := postJSON(t, server, secret, "/v1/releases", "candidate-schema-release", map[string]any{"product_id": dataField(t, p, "id"), "version": "1"}, 201)
	c := postJSON(t, server, secret, "/v1/release-candidates", "candidate-schema-create", map[string]any{"release_id": dataField(t, r, "id"), "name": "Candidate"}, 201)
	id := dataField(t, c, "id")
	promoted := postJSONWithIfMatch(t, server, secret, "/v1/release-candidates/"+id+"/promote", "candidate-schema-promote", 1, map[string]any{"reason": "reviewed"}, 200)
	body, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["ReleaseCandidate"]
	for _, field := range schema.Required {
		if _, ok := schema.Properties[field]; !ok {
			t.Fatal("candidate schema requires an undefined property", field)
		}
	}
	if revision := schema.Properties["revision"]; revision["type"] != "integer" || revision["format"] != "int64" || revision["minimum"] != float64(1) {
		t.Fatal("candidate revision schema does not match positive integer runtime contract", revision)
	}
	for _, tc := range []struct {
		body     string
		revision int
	}{{c, 1}, {promoted, 2}, {getJSON(t, server, secret, "/v1/release-candidates/"+id, 200), 2}} {
		var v struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(tc.body), &v); err != nil {
			t.Fatal(err)
		}
		if v.Data["revision"] != float64(tc.revision) {
			t.Fatal("candidate response revision changed", v.Data)
		}
		for field := range v.Data {
			if _, ok := schema.Properties[field]; !ok {
				t.Fatal("candidate returned undeclared property", field)
			}
		}
		for _, field := range schema.Required {
			if _, ok := v.Data[field]; !ok {
				t.Fatal("candidate response omitted required property", field)
			}
		}
	}
}
