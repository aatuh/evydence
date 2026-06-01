package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestSampleCustomerPackageManifestGolden(t *testing.T) {
	body, err := os.ReadFile("../../examples/end-to-end-release-evidence/sample-customer-package-manifest.json")
	if err != nil {
		t.Fatalf("read manifest fixture: %v", err)
	}
	expectedBody, err := os.ReadFile("../../examples/end-to-end-release-evidence/sample-customer-package-manifest.sha256")
	if err != nil {
		t.Fatalf("read manifest checksum fixture: %v", err)
	}
	expectedHash := strings.Fields(string(expectedBody))[0]
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != expectedHash {
		t.Fatalf("sample customer package manifest drifted: got sha256 %s want %s; update the fixture and checksum intentionally", got, expectedHash)
	}

	var manifest map[string]any
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("decode manifest fixture: %v", err)
	}
	for _, key := range []string{
		"schema_version",
		"package_version",
		"package_id",
		"product",
		"release",
		"redaction_profile",
		"readiness_summary",
		"verification_material",
		"reviewer_checklist",
		"customer_decision_export",
		"limitations",
		"non_claims",
	} {
		if _, ok := manifest[key]; !ok {
			t.Fatalf("manifest fixture missing required key %q", key)
		}
	}
	if manifest["schema_version"] != domain.CustomerPackageSchemaVersion || manifest["package_version"] != domain.CustomerPackageSchemaVersion {
		t.Fatalf("manifest fixture schema version = schema:%v package:%v want %s", manifest["schema_version"], manifest["package_version"], domain.CustomerPackageSchemaVersion)
	}
	checklist, ok := manifest["reviewer_checklist"].([]any)
	if !ok || len(checklist) < 6 {
		t.Fatalf("manifest fixture reviewer checklist missing expected proof-path entries: %#v", manifest["reviewer_checklist"])
	}
	seen := map[string]bool{}
	for _, item := range checklist {
		entry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("manifest fixture reviewer checklist entry is not an object: %#v", item)
		}
		id, _ := entry["id"].(string)
		seen[id] = true
	}
	for _, id := range []string{"package_scope", "included_evidence", "excluded_evidence", "hash_signature_verification", "non_claims", "escalation_path"} {
		if !seen[id] {
			t.Fatalf("manifest fixture reviewer checklist missing %q: %#v", id, checklist)
		}
	}
	decisions, ok := manifest["vulnerability_decisions"].([]any)
	if !ok || len(decisions) == 0 {
		t.Fatalf("manifest fixture missing vulnerability decisions: %#v", manifest["vulnerability_decisions"])
	}
	firstDecision, ok := decisions[0].(map[string]any)
	if !ok {
		t.Fatalf("manifest fixture decision is not an object: %#v", decisions[0])
	}
	for _, key := range []string{"reviewed_at", "review_due_at", "sbom_id", "sbom_component_purl", "sbom_component_name", "supporting_refs"} {
		if firstDecision[key] == "" || firstDecision[key] == nil {
			t.Fatalf("manifest fixture decision missing %q: %#v", key, firstDecision)
		}
	}
	export, ok := manifest["customer_decision_export"].(map[string]any)
	if !ok || export["file"] != "vulnerability-decisions.json" || export["schema_version"] != "customer-vulnerability-decisions.v1.0.0" {
		t.Fatalf("manifest fixture customer decision export missing expected metadata: %#v", manifest["customer_decision_export"])
	}
}
