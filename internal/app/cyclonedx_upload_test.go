package app

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestValidatedCycloneDXUploadPersistsNormalizationMetadata(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
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
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar", "application/gzip", sampleDigest("artifact"), 42)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0","properties":[{"name":"source","value":"generator"}]}],"dependencies":[{"ref":"pkg:generic/api@1.0.0","dependsOn":[]}]}`)

	sbom, err := ledger.UploadSBOMPayload(ctx, actor, release.ID, artifact.ID, BytesPayloadSource(raw))
	if err != nil {
		t.Fatal(err)
	}
	if sbom.SpecVersion != "1.6" || sbom.ComponentCount != 1 || len(sbom.Components) != 1 || sbom.Components[0].PURL != "pkg:generic/api@1.0.0" {
		t.Fatalf("sbom=%#v", sbom)
	}
	evidence, err := ledger.GetEvidence(ctx, actor, sbom.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Metadata["parser_version"] != ParserVersionCycloneDXJSON || evidence.Metadata["dependency_count"] != 1 || len(evidence.Limitations) != 1 {
		t.Fatalf("evidence=%#v", evidence)
	}
}

func TestValidatedCycloneDXUploadRejectsSchemaInvalidBeforePublication(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
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
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar", "application/gzip", sampleDigest("artifact"), 42)
	if err != nil {
		t.Fatal(err)
	}

	beforeItems, err := ledger.ListEvidence(ctx, actor, "", "")
	if err != nil {
		t.Fatal(err)
	}
	before := len(beforeItems)
	_, err = ledger.UploadSBOMPayload(ctx, actor, release.ID, artifact.ID,
		BytesPayloadSource([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"missing-type"}]}`)))
	if err != ErrValidation {
		t.Fatalf("err=%v, want validation", err)
	}
	afterItems, err := ledger.ListEvidence(ctx, actor, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if after := len(afterItems); after != before {
		t.Fatalf("invalid upload published evidence: before=%d after=%d", before, after)
	}
}

func TestValidatedCycloneDXUploadRejectsUnknownTargetBeforeOpeningPayload(t *testing.T) {
	ctx := context.Background()
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	source := BytesPayloadSource(raw)
	openCount := 0
	source.Open = func() (io.ReadCloser, error) {
		openCount++
		return io.NopCloser(strings.NewReader(string(raw))), nil
	}

	if _, err := ledger.UploadSBOMPayload(ctx, actor, "missing-release", "", source); err == nil {
		t.Fatal("missing release unexpectedly accepted")
	}
	if openCount != 0 {
		t.Fatalf("payload opened %d times before target authorization", openCount)
	}
}
