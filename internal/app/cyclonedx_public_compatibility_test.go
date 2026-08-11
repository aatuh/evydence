package app

import (
	"context"
	"testing"
)

func TestPublicCycloneDXUploadAcceptsMinimal16Document(t *testing.T) {
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

	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, "", raw)
	if err != nil {
		t.Fatalf("minimal CycloneDX 1.6 upload rejected: %v", err)
	}
	if sbom.SpecVersion != "1.6" {
		t.Fatalf("spec_version=%q want=1.6", sbom.SpecVersion)
	}
	if len(sbom.Components) != 0 {
		t.Fatalf("components=%#v want empty", sbom.Components)
	}
	if _, err := ledger.GetEvidence(ctx, actor, sbom.EvidenceID); err != nil {
		t.Fatalf("published SBOM evidence unavailable: %v", err)
	}
}
