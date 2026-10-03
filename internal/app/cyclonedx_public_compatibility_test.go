package app

import (
	"context"
	"testing"
)

func TestPublicCycloneDXUploadAcceptsStandardFieldsOutsideNormalization(t *testing.T) {
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

	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","metadata":{"timestamp":"2026-08-09T00:00:00Z"},"components":[{"type":"library","name":"api","licenses":[{"license":{"id":"Apache-2.0"}}]}]}`)
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, "", raw)
	if err != nil {
		t.Fatalf("standard CycloneDX 1.6 upload rejected: %v", err)
	}
	if sbom.SpecVersion != "1.6" {
		t.Fatalf("spec_version=%q want=1.6", sbom.SpecVersion)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].Name != "api" {
		t.Fatalf("components=%#v", sbom.Components)
	}
	evidence, err := ledger.GetEvidence(ctx, actor, sbom.EvidenceID)
	if err != nil {
		t.Fatalf("published SBOM evidence unavailable: %v", err)
	}
	if evidence.Metadata["parser_version"] != ParserVersionCycloneDXJSON || len(evidence.Limitations) == 0 {
		t.Fatalf("evidence does not expose conformant-parser metadata: %#v", evidence)
	}
}
