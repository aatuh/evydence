package httpapi

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestControlTemplateInstallBodyContractInLocalProfile(t *testing.T) {
	server, secret := testServer(t)
	path := "/v1/control-framework-template-packs/evydence-cra-readiness/install"
	response := postRaw(t, server, secret, path, "empty-template-body", nil, 201)
	if dataField(t, response, "slug") != "evydence-cra-readiness" {
		t.Fatal("empty-body install changed", response)
	}
	second := "/v1/control-framework-template-packs/nist-ssdf-lite/install"
	for i, bad := range []string{"{", "[]", "null", `{"unknown":1}`, `{} {}`, `{"tenant_id":"other"}`} {
		postRaw(t, server, secret, second, fmt.Sprintf("invalid-local-template-body-%d", i), []byte(bad), 400)
	}
	postRaw(t, server, secret, second, "valid-local-template-body", []byte("{}"), 201)
	postRaw(t, server, secret, "/v1/control-framework-template-packs/bad%00slug/install", "nul-local-template", nil, 400)
	postRaw(t, server, secret, "/v1/control-framework-template-packs/%FF/install", "utf8-local-template", nil, 400)
	body, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Required bool `json:"required"`
			} `json:"requestBody"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	operation, ok := doc.Paths["/v1/control-framework-template-packs/{slug}/install"]["post"]
	if !ok || operation.RequestBody.Required {
		t.Fatal("OpenAPI requires the optional empty-object body")
	}
}
