package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestValidatedCycloneDXUploadPreservesRawBytesExactly(t *testing.T) {
	ctx := context.Background()
	objects := newTestObjectStore()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, ObjectStore: objects})
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
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar", "application/gzip", sampleDigest("raw-preservation-artifact"), 42)
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte("{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.6\",\n  \"components\": [\n    {\"type\":\"library\", \"name\":\"api\", \"properties\":[{\"name\":\"source\",\"value\":\"exact bytes\"}]}\n  ]\n}\n")
	sbom, err := ledger.releaseEvidenceService().uploadValidatedCycloneDXSBOMPayload(
		ctx, actor, release.ID, artifact.ID, BytesPayloadSource(raw), uploadCycloneDXValidator(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ledger.GetEvidence(ctx, actor, sbom.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimPrefix(evidence.PayloadRef, "object://")
	if key == "" || key == evidence.PayloadRef {
		t.Fatalf("payload ref=%q", evidence.PayloadRef)
	}
	object, err := objects.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(object.Bytes, raw) {
		t.Fatalf("stored CycloneDX bytes changed:\nwant=%q\n got=%q", raw, object.Bytes)
	}
	if object.Digest != hashBytes(raw) || evidence.PayloadHash != hashBytes(raw) {
		t.Fatalf("digest binding object=%q evidence=%q want=%q", object.Digest, evidence.PayloadHash, hashBytes(raw))
	}
}
