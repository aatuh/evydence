package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestCustomerCreationOpenAPIConstrainsOnlyNewRequest(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties  map[string]map[string]any `json:"properties"`
				Description string                    `json:"description"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	in := doc.Components.Schemas["CreateCustomerPackageRequest"].Properties
	for _, name := range []string{"product_id", "release_id", "redaction_profile_id"} {
		if in[name]["maxLength"] != float64(packageapp.MaxCustomerPackageIDBytes) {
			t.Fatal("raw identifier bound missing", name)
		}
	}
	if in["title"]["maxLength"] != float64(packageapp.MaxCustomerPackageTitleBytes) {
		t.Fatal("raw title bound missing")
	}
	if doc.Components.Schemas["CustomerSecurityPackage"].Properties["title"]["maxLength"] != nil {
		t.Fatal("historical response constrained")
	}
	if !strings.Contains(doc.Components.Schemas["CreateCustomerPackageRequest"].Description, "Duplicate/case-aliased keys and explicit null fields are rejected") {
		t.Fatal("strict creation JSON behavior missing from published contract")
	}
}

func TestCustomerCreationLegacyHTTPUsesSharedRawInputBounds(t *testing.T) {
	s, secret := testServer(t)
	product := dataField(t, postJSON(t, s, secret, "/v1/products", "creation-product", map[string]any{"name": "Product", "slug": "creation-product"}, http.StatusCreated), "id")
	profile := dataField(t, postJSON(t, s, secret, "/v1/redaction-profiles", "creation-profile", map[string]any{"preset": "customer_safe"}, http.StatusCreated), "id")
	base := map[string]any{"product_id": product, "redaction_profile_id": profile, "title": "Review", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}
	for i, tc := range []struct {
		field string
		value any
	}{
		{"product_id", strings.Repeat(" ", 1024) + product},
		{"release_id", strings.Repeat("x", 1025)},
		{"redaction_profile_id", "bad\x00"},
		{"title", strings.Repeat("x", 4097)},
		{"title", strings.Repeat("é", 2049)},
		{"title", " "},
		{"expires_at", time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)},
	} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body[tc.field] = tc.value
		postJSON(t, s, secret, "/v1/customer-packages", fmt.Sprintf("creation-bad-%d", i), body, http.StatusBadRequest)
	}
	base["title"] = strings.Repeat("x", 4096)
	result := postJSON(t, s, secret, "/v1/customer-packages", "creation-valid", base, http.StatusCreated)
	if dataField(t, result, "title") != base["title"] {
		t.Fatal("boundary title changed")
	}
}
