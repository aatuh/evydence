package httpapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestProjectSchemasMatchAcceptedRequestAndReturnedResource(t *testing.T) {
	server, secret := testServer(t)
	productJSON := postJSON(t, server, secret, "/v1/products", "schema-product", map[string]any{"name": "Product", "slug": "schema-product"}, 201)
	var parent struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(productJSON), &parent); err != nil || parent.Data.ID == "" {
		t.Fatal("missing parent ID", err)
	}
	product := parent.Data.ID
	body := postRaw(t, server, secret, "/v1/projects", "schema-project", []byte(`{"product_id":"`+product+`","name":"Project"}`), 201)
	postRaw(t, server, secret, "/v1/projects", "schema-project-slug", []byte(`{"product_id":"`+product+`","name":"Project","slug":"unsupported"}`), 400)
	var response struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	doc, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(doc, &spec); err != nil {
		t.Fatal(err)
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, spec["components"])["schemas"])
	keys := func(v map[string]any) []string {
		var names []string
		for key := range v {
			names = append(names, key)
		}
		sort.Strings(names)
		return names
	}
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{"CreateProjectRequest", []string{"name", "product_id"}},
		{"Project", keys(response.Data)},
	} {
		schema := asStringAnyMap(t, schemas[tc.name])
		if got := keys(asStringAnyMap(t, schema["properties"])); !reflect.DeepEqual(got, tc.fields) {
			t.Fatal("project schema advertises unsupported fields", tc.name, got, tc.fields)
		}
		var required []string
		for _, field := range schema["required"].([]any) {
			required = append(required, field.(string))
		}
		sort.Strings(required)
		if !reflect.DeepEqual(required, tc.fields) {
			t.Fatal("project schema requires missing fields", tc.name, required, tc.fields)
		}
	}
}
