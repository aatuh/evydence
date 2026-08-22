package app

import (
	"context"
	"errors"
	"testing"
)

func TestValidatedCycloneDXUploadRejectsSchemaInvalidBeforeObjectStaging(t *testing.T) {
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

	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"missing-type"}]}`)
	source := BytesPayloadSource(raw)
	_, err = ledger.releaseEvidenceService().uploadValidatedCycloneDXSBOMPayload(
		ctx, actor, release.ID, "", source, uploadCycloneDXValidator(t),
	)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err=%v, want validation", err)
	}

	payload, err := newStagedObjectPayload(actor.TenantID, "application/vnd.cyclonedx+json", source.Digest, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Get(ctx, payload.StagingKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("schema-invalid upload left staging object: %v", err)
	}
	if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("schema-invalid upload left final object: %v", err)
	}
}
