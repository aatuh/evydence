package app

import (
	"errors"
	"strings"
	"testing"
)

func FuzzObjectPayloadKeyRoundTrip(f *testing.F) {
	for _, tenant := range []string{"ten_1", "ten_12", "tenant\u00e9", "", "..", "ten/other", " ten_1", "ten\x00other"} {
		f.Add(tenant, []byte("payload"), true)
		f.Add(tenant, []byte{}, false)
	}
	f.Fuzz(func(t *testing.T, tenant string, payload []byte, staged bool) {
		if len(tenant) > 512 || len(payload) > 4096 {
			return
		}
		digest := hashBytes(payload)
		staging, final, err := CanonicalObjectPayloadKeys(tenant, digest)
		if ValidateObjectTenantID(tenant) != nil {
			if !errors.Is(err, ErrValidation) || staging != "" || final != "" {
				t.Fatal("invalid tenant produced an object namespace")
			}
			return
		}
		if err != nil || staging == final {
			t.Fatalf("valid tenant did not produce distinct object lifecycle keys: %v", err)
		}
		key, wantKind := final, ObjectPayloadKeyFinal
		if staged {
			key, wantKind = staging, ObjectPayloadKeyStaging
		}
		gotTenant, gotDigest, gotKind, err := ParseObjectPayloadKey(key)
		if err != nil || gotTenant != tenant || gotDigest != digest || gotKind != wantKind {
			t.Fatalf("object identity did not round-trip: %v", err)
		}
		if !strings.HasPrefix(key, "tenants/"+tenant+"/") || ValidateTenantObjectKey(tenant, key) != nil {
			t.Fatal("object escaped its exact tenant prefix")
		}
		foreign := "different"
		if tenant == foreign {
			foreign = "another"
		}
		if !errors.Is(ValidateTenantObjectKey(foreign, key), ErrValidation) {
			t.Fatal("foreign tenant accepted generated object key")
		}
	})
}

func FuzzParseObjectPayloadKey(f *testing.F) {
	digest := strings.Repeat("a", 64)
	for _, key := range []string{
		"tenants/ten_1/payloads/sha256/" + digest,
		"tenants/ten_1/staging/sha256/" + digest,
		"tenants/ten_1/../ten_2/payloads/sha256/" + digest,
		"tenants/ten_1/payloads/sha256/" + strings.ToUpper(digest),
		"tenants//payloads/sha256/" + digest, "", "tenants\\ten_1\\raw",
	} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if len(key) > 4096 {
			return
		}
		tenant, digest, kind, err := ParseObjectPayloadKey(key)
		if err != nil {
			if !errors.Is(err, ErrValidation) || tenant != "" || digest != "" || kind != "" {
				t.Fatal("rejected object key returned partial identity")
			}
			return
		}
		encoded, err := CanonicalObjectPayloadKey(tenant, digest, kind)
		if err != nil || encoded != key || ValidateTenantObjectKey(tenant, key) != nil {
			t.Fatalf("accepted object key lost canonical ownership: %v", err)
		}
	})
}

func FuzzIdempotencyRecordKeyRoundTrip(f *testing.F) {
	f.Add("ten_1", "api_key:key_1", "POST", "/v1/evidence", "request_1")
	f.Add("tenant\x00scope", "user:actor.with:delimiters", "", "/a\x00b", "opaque.\x00key")
	f.Add("\u00e9", "\U0001f600", "GET", "/v1/a?b=c", "\xff")
	f.Add("", "actor", "POST", "/", "key")
	f.Add("tenant", "", "POST", "/", "key")
	f.Add("tenant", "actor", "POST", "/", "")
	f.Fuzz(func(t *testing.T, tenant, actor, method, path, key string) {
		for _, value := range []string{tenant, actor, method, path, key} {
			if len(value) > 4096 {
				return
			}
		}
		encoded := NewIdempotencyRecordKey(tenant, actor, method, path, key)
		actual, ok := ParseIdempotencyRecordKey(encoded)
		if tenant == "" || actor == "" || key == "" {
			if ok || actual != (IdempotencyRecordKey{}) {
				t.Fatal("key without required ownership returned a usable identity")
			}
			return
		}
		want := IdempotencyRecordKey{
			TenantID: tenant, ActorID: actor, Method: method,
			Path: path, IdempotencyKey: key,
		}
		if !ok || actual != want {
			t.Fatal("opaque idempotency fields did not round-trip exactly")
		}
		foreign := NewIdempotencyRecordKey(tenant+"-foreign", actor, method, path, key)
		if foreign == encoded {
			t.Fatal("different tenants collided in encoded idempotency namespace")
		}
	})
}

func FuzzParseIdempotencyRecordKey(f *testing.F) {
	f.Add(NewIdempotencyRecordKey("ten_1", "api_key:key_1", "POST", "/v1/evidence", "request_1"))
	f.Add("ten_1\x00user:actor\x00POST\x00/v1/evidence\x00request_1")
	f.Add("v2:not.base64")
	f.Add("v2:!!!!.....")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16<<10 {
			return
		}
		actual, ok := ParseIdempotencyRecordKey(raw)
		if !ok {
			if actual != (IdempotencyRecordKey{}) {
				t.Fatal("rejected record key returned partial identity")
			}
			return
		}
		if actual.TenantID == "" || actual.ActorID == "" || actual.IdempotencyKey == "" {
			t.Fatal("accepted record key has no ownership or request identity")
		}
		// Legacy NUL-separated keys remain readable; normalization must retain
		// every semantic field without requiring legacy spelling to be v2.
		encoded := NewIdempotencyRecordKey(actual.TenantID, actual.ActorID,
			actual.Method, actual.Path, actual.IdempotencyKey)
		roundTrip, valid := ParseIdempotencyRecordKey(encoded)
		if !valid || roundTrip != actual {
			t.Fatal("accepted record key lost fields during v2 normalization")
		}
	})
}
