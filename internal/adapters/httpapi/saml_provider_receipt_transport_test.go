package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSAMLReceiptTransportPreservesCorrelationAndRejectsAliasedOrNullState(t *testing.T) {
	body := []byte(`{"provider_type":"saml","provider_id":"provider","subject":"subject","saml_assertion":"signed-xml","authentication_request_id":"samlreq_fixture","state_secret":"evylogin_fixture"}`)
	in, err := decodeProviderVerificationRequest(body)
	if err != nil || in.AuthenticationRequestID != "samlreq_fixture" || in.StateSecret != "evylogin_fixture" {
		t.Fatal("receipt decoder lost SAML correlation", err)
	}
	for _, bad := range []string{`{"provider_type":"saml","authentication_request_id":null}`, `{"provider_type":"saml","state_secret":null}`, `{"provider_type":"saml","STATE_SECRET":"value"}`, `{"provider_type":"saml","state_secret":"one","state_secret":"two"}`} {
		if _, err := decodeProviderVerificationRequest([]byte(bad)); err == nil {
			t.Fatal("ambiguous receipt state accepted")
		}
	}
}

func TestSAMLReceiptSchemaRequiresStateOnlyForAssertionAssessment(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	schema := asStringAnyMap(t, asStringAnyMap(t, doc["components"])["schemas"])["VerifyProviderIdentityRequest"]
	c := jsonschema.NewCompiler()
	if err := c.AddResource("https://schema.example.test/receipt", schema); err != nil {
		t.Fatal(err)
	}
	compiled, err := c.Compile("https://schema.example.test/receipt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, protocol, assertion, request, state string
		valid                                     bool
	}{
		{name: "saml metadata", protocol: "saml", valid: true},
		{name: "oidc metadata", protocol: "oidc", valid: true},
		{name: "correlated saml", protocol: "saml", assertion: "signed xml", request: "samlreq_fixture", state: "evylogin_" + strings.Repeat("A", 43), valid: true},
		{name: "missing saml state", protocol: "saml", assertion: "signed xml"},
		{name: "missing saml request", protocol: "saml", assertion: "signed xml", state: "evylogin_" + strings.Repeat("A", 43)},
		{name: "state on oidc", protocol: "oidc", request: "samlreq_fixture", state: "evylogin_" + strings.Repeat("A", 43)},
		{name: "state on metadata", protocol: "saml", request: "samlreq_fixture", state: "evylogin_" + strings.Repeat("A", 43)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := map[string]any{"provider_type": tc.protocol, "provider_id": "provider", "subject": "subject"}
			if tc.assertion != "" {
				v["saml_assertion"] = tc.assertion
			}
			if tc.request != "" {
				v["authentication_request_id"] = tc.request
			}
			if tc.state != "" {
				v["state_secret"] = tc.state
			}
			if err := compiled.Validate(v); (err == nil) != tc.valid {
				t.Fatalf("schema validity=%v want %v: %v", err == nil, tc.valid, err)
			}
		})
	}
}
