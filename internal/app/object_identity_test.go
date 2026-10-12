package app

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanonicalObjectPayloadIdentityRoundTrip(t *testing.T) {
	digest := hashBytes([]byte("identity"))
	staging, final, err := CanonicalObjectPayloadKeys("ten_identity", digest)
	if err != nil {
		t.Fatal(err)
	}
	if staging != "tenants/ten_identity/staging/sha256/"+strings.TrimPrefix(digest, "sha256:") {
		t.Fatalf("staging key=%q", staging)
	}
	if final != "tenants/ten_identity/payloads/sha256/"+strings.TrimPrefix(digest, "sha256:") {
		t.Fatalf("final key=%q", final)
	}
	for key, wantKind := range map[string]ObjectPayloadKeyKind{staging: ObjectPayloadKeyStaging, final: ObjectPayloadKeyFinal} {
		tenantID, parsedDigest, kind, err := ParseObjectPayloadKey(key)
		if err != nil || tenantID != "ten_identity" || parsedDigest != digest || kind != wantKind {
			t.Fatalf("parse %q = %q %q %q err=%v", key, tenantID, parsedDigest, kind, err)
		}
	}
}

func TestObjectIdentityRejectsAmbiguousTenantKeyAndDigestForms(t *testing.T) {
	canonicalDigest := "sha256:" + strings.Repeat("a", 64)
	for _, tenantID := range []string{"", ".", "..", " ten_1", "ten_1 ", "ten/other", `tenant\\segment`, "ten\ninvalid"} {
		if err := ValidateObjectTenantID(tenantID); !errors.Is(err, ErrValidation) {
			t.Fatalf("tenant %q err=%v, want validation", tenantID, err)
		}
	}
	for _, digest := range []string{
		"", "sha512:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64), canonicalDigest + " ",
	} {
		if err := ValidateCanonicalObjectDigest(digest); !errors.Is(err, ErrValidation) {
			t.Fatalf("digest %q err=%v, want validation", digest, err)
		}
	}
	for _, key := range []string{
		"", "/tenants/ten_1/raw", "tenants/ten_1", "tenants//raw", "tenants/../ten_1/raw",
		"tenants/ten_1/../ten_2/raw", `tenants\\ten_1\\raw`, "tenants/ten_1/raw\nname", " tenants/ten_1/raw",
	} {
		if _, err := TenantIDFromObjectKey(key); !errors.Is(err, ErrValidation) {
			t.Fatalf("key %q err=%v, want validation", key, err)
		}
	}
	if err := ValidateTenantObjectKey("ten_1", "tenants/ten_2/raw"); !errors.Is(err, ErrValidation) {
		t.Fatalf("cross-tenant key err=%v, want validation", err)
	}
	if _, _, _, err := ParseObjectPayloadKey("tenants/ten_1/payloads/sha256/" + strings.Repeat("A", 64)); !errors.Is(err, ErrValidation) {
		t.Fatalf("noncanonical payload key err=%v, want validation", err)
	}
}

func TestObjectPayloadValidationRequiresCanonicalIdentity(t *testing.T) {
	now := time.Now().UTC()
	digest := hashBytes([]byte("payload"))
	staging, final, err := CanonicalObjectPayloadKeys("ten_identity", digest)
	if err != nil {
		t.Fatal(err)
	}
	payload := ObjectPayload{
		TenantID: "ten_identity", Digest: digest, Size: 7, MediaType: "application/json",
		StagingKey: staging, FinalKey: final, Status: ObjectPayloadStaged, CreatedAt: now, UpdatedAt: now,
	}
	if err := ValidateObjectPayloadForRepository(payload); err != nil {
		t.Fatalf("canonical payload rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ObjectPayload){
		"staging traversal": func(p *ObjectPayload) {
			p.StagingKey = "tenants/ten_identity/staging/../payloads/sha256/" + strings.TrimPrefix(digest, "sha256:")
		},
		"foreign final": func(p *ObjectPayload) { p.FinalKey = strings.Replace(p.FinalKey, "ten_identity", "ten_other", 1) },
		"wrong digest key": func(p *ObjectPayload) {
			p.FinalKey = strings.TrimSuffix(p.FinalKey, strings.TrimPrefix(digest, "sha256:")) + strings.Repeat("b", 64)
		},
		"bad media type": func(p *ObjectPayload) { p.MediaType = "not a media type" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := payload
			mutate(&candidate)
			if err := ValidateObjectPayloadForRepository(candidate); !errors.Is(err, ErrValidation) {
				t.Fatalf("candidate err=%v, want validation", err)
			}
		})
	}
}

func TestVerifyObjectPayloadReadChecksBytesTenantSizeDigestAndMediaType(t *testing.T) {
	now := time.Now().UTC()
	body := []byte("payload")
	digest := hashBytes(body)
	staging, final, err := CanonicalObjectPayloadKeys("ten_read", digest)
	if err != nil {
		t.Fatal(err)
	}
	payload := ObjectPayload{TenantID: "ten_read", Digest: digest, Size: int64(len(body)), MediaType: "application/json; charset=utf-8", StagingKey: staging, FinalKey: final, Status: ObjectPayloadFinalized, CreatedAt: now, UpdatedAt: now}
	object := Object{Key: final, TenantID: payload.TenantID, Digest: digest, MediaType: "application/json; charset=utf-8", Bytes: body}
	if err := VerifyObjectPayloadRead(payload, object, final); err != nil {
		t.Fatalf("valid read rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Object){
		"tenant":     func(o *Object) { o.TenantID = "ten_other" },
		"key":        func(o *Object) { o.Key = staging },
		"digest":     func(o *Object) { o.Digest = "sha256:" + strings.Repeat("b", 64) },
		"bytes":      func(o *Object) { o.Bytes = []byte("payloae") },
		"byte count": func(o *Object) { o.Bytes = append(o.Bytes, '!') },
		"media type": func(o *Object) { o.MediaType = "text/plain" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := object
			candidate.Bytes = append([]byte(nil), object.Bytes...)
			mutate(&candidate)
			if err := VerifyObjectPayloadRead(payload, candidate, final); !errors.Is(err, ErrValidation) {
				t.Fatalf("candidate err=%v, want validation", err)
			}
		})
	}
}
