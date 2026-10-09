package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCandidateTransitionSchemaRequiresReasonMatchingHTTP(t *testing.T) {
	server, secret := testServer(t)
	p := postJSON(t, server, secret, "/v1/products", "reason-product", map[string]any{"name": "Product", "slug": "product"}, 201)
	r := postJSON(t, server, secret, "/v1/releases", "reason-release", map[string]any{"product_id": dataField(t, p, "id"), "version": "1"}, 201)
	c := postJSON(t, server, secret, "/v1/release-candidates", "reason-candidate", map[string]any{"release_id": dataField(t, r, "id"), "name": "Candidate"}, 201)
	for _, action := range []string{"promote", "reject"} {
		postJSONWithIfMatch(t, server, secret, "/v1/release-candidates/"+dataField(t, c, "id")+"/"+action, "missing-reason-"+action, 1, map[string]any{}, 400)
	}
	postJSONWithIfMatch(t, server, secret, "/v1/release-candidates/"+dataField(t, c, "id")+"/promote", "valid-reason", 1, map[string]any{"reason": "reviewed"}, 200)
	body, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required []string `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if required := doc.Components.Schemas["ReleaseCandidateTransitionRequest"].Required; !reflect.DeepEqual(required, []string{"reason"}) {
		t.Fatal("schema permits omission rejected by both transition endpoints", required)
	}
}
