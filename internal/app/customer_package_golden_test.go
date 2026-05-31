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
}
