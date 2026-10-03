package httpapi

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestControlCreationRejectsNonNullableJSONInLocalProfile(t *testing.T) {
	server, secret := testServer(t)
	fw := postJSON(t, server, secret, "/v1/control-frameworks", "validation-framework", map[string]any{"name": "Framework", "version": "1"}, 201)
	for i, field := range []string{"slug", "description"} {
		postRaw(t, server, secret, "/v1/control-frameworks", fmt.Sprintf("null-local-framework-%d", i), []byte(`{"name":"Invalid","version":"1","`+field+`":null}`), 400)
	}
	base := `"framework_id":"` + dataField(t, fw, "id") + `","code":"C","title":"Title","objective":"Objective"`
	for i, bad := range []string{
		`"applicability":[null]`, `"limitations":[null]`, `"evidence_requirements":[null]`,
		`"evidence_requirements":null`, `"applicability":null`, `"limitations":null`,
		`"evidence_requirements":[{"type":"sbom"}]`,
		`"evidence_requirements":[{"type":"sbom","required":null}]`,
		`"evidence_requirements":[{"type":"sbom","required":true,"freshness_days":null}]`,
	} {
		postRaw(t, server, secret, "/v1/controls", fmt.Sprintf("bad-local-control-%d", i), []byte(`{`+base+`,`+bad+`}`), 400)
	}
	body := `{` + base + `,"evidence_requirements":[{"type":"build","required":false}]}`
	response := postRaw(t, server, secret, "/v1/controls", "valid-local-control", []byte(body), 201)
	var parsed struct {
		Data domain.SecurityControl `json:"data"`
	}
	if err := json.Unmarshal([]byte(response), &parsed); err != nil || len(parsed.Data.EvidenceRequirements) != 1 || parsed.Data.EvidenceRequirements[0].Required || parsed.Data.EvidenceRequirements[0].Type != "build" {
		t.Fatal("explicit false requirement rejected or changed", parsed, err)
	}
	frameworks, err := server.ledger.ListControlFrameworks(t.Context(), domain.Actor{TenantID: parsed.Data.TenantID, KeyID: "test", Scopes: []string{"controls:read"}})
	if err != nil || len(frameworks) != 1 {
		t.Fatal("invalid nullable framework wrote records", frameworks, err)
	}
}
