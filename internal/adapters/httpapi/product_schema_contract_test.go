package httpapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestProductSchemaMatchesActualCreateReadAndListFields(t *testing.T) {
	server, secret := catalogQueryTestServer(t)
	created := postRaw(t, server, secret, "/v1/products", "schema-product", []byte(`{"name":"Product","slug":"product"}`), 201)
	id := dataField(t, created, "id")
	for _, body := range []string{created, getJSON(t, server, secret, "/v1/products/"+id, 200)} {
		var envelope struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Fatal(err)
		}
		assertProductSchemaFields(t, server, envelope.Data)
	}
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(getJSON(t, server, secret, "/v1/products", 200)), &list); err != nil || len(list.Data) != 1 {
		t.Fatal("product list decode/count", err, list)
	}
	assertProductSchemaFields(t, server, list.Data[0])
}

func assertProductSchemaFields(t *testing.T, server *Server, actual map[string]any) {
	t.Helper()
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
				Required   []string       `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	doc, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(doc, &document); err != nil {
		t.Fatal(err)
	}
	schema, ok := document.Components.Schemas["Product"]
	if !ok {
		t.Fatal("Product schema missing")
	}
	var responseKeys, schemaKeys []string
	for key := range actual {
		responseKeys = append(responseKeys, key)
	}
	for key := range schema.Properties {
		schemaKeys = append(schemaKeys, key)
	}
	sort.Strings(responseKeys)
	sort.Strings(schemaKeys)
	sort.Strings(schema.Required)
	want := []string{"created_at", "id", "name", "slug", "tenant_id"}
	if !reflect.DeepEqual(responseKeys, want) || !reflect.DeepEqual(schemaKeys, want) || !reflect.DeepEqual(schema.Required, want) {
		t.Fatal("product schema advertises or requires unsupported response fields", responseKeys, schemaKeys, schema.Required)
	}
}
