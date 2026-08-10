package app

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestPublicCycloneDXUploadUsesPinnedConformantParser(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "API", "api")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{
		"$schema":"http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"version":1,
		"metadata":{"timestamp":"2026-08-10T06:30:00Z"},
		"components":[{
			"type":"library",
			"name":"api",
			"properties":[{"name":"source","value":"public-upload"}]
		}],
		"services":[{"name":"gateway"}],
		"properties":[{"name":"root","value":"preserved"}]
	}`)
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, "", raw)
	if err != nil {
		t.Fatalf("standard CycloneDX 1.6 upload rejected: %v", err)
	}
	if sbom.SpecVersion != "1.6" || len(sbom.Components) != 1 || sbom.Components[0].Name != "api" {
		t.Fatalf("sbom=%#v", sbom)
	}
	evidence, err := ledger.GetEvidence(ctx, actor, sbom.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := evidence.Metadata["parser_version"].(string); got != ParserVersionCycloneDXJSON {
		t.Fatalf("parser_version=%q want=%q", got, ParserVersionCycloneDXJSON)
	}
	paths, ok := evidence.Metadata["unsupported_normalization"].([]string)
	if !ok {
		t.Fatalf("unsupported_normalization=%#v", evidence.Metadata["unsupported_normalization"])
	}
	for _, want := range []string{"$schema", "metadata", "properties", "services", "version", "components[].properties"} {
		if !slices.Contains(paths, want) {
			t.Fatalf("unsupported paths=%#v missing %q", paths, want)
		}
	}
	if len(evidence.Limitations) == 0 {
		t.Fatal("expected explicit normalization limitation")
	}
}

func TestPublicCycloneDXUploadRejectsOfficialSchemaViolation(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "API", "api")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","definitelyNotCycloneDX":true}`)
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, "", raw); !errors.Is(err, ErrValidation) {
		t.Fatalf("schema violation err=%v, want validation failure", err)
	}
	items, err := ledger.ListEvidence(ctx, actor, release.ID, "sbom")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("schema-invalid upload published evidence: %#v", items)
	}
}
