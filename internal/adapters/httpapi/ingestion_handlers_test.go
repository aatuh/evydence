package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestStreamRequestPayloadStreamsAndEnforcesExactLimit(t *testing.T) {
	const payloadSize = 2 << 20
	reader := &repeatingByteReader{remaining: payloadSize, value: 'x'}
	req := httptest.NewRequest(http.MethodPost, "/v1/vulnerability-scans", io.NopCloser(reader))
	source, cleanup, err := streamRequestPayload(req, payloadSize)
	if err != nil {
		t.Fatalf("stream payload: %v", err)
	}
	defer cleanup()
	if source.Size != payloadSize || reader.maxRead >= payloadSize {
		t.Fatalf("stream source=%#v max read=%d", source, reader.maxRead)
	}
	opened, err := source.Open()
	if err != nil {
		t.Fatalf("open staged request: %v", err)
	}
	defer opened.Close()
	first := make([]byte, 16)
	if _, err := io.ReadFull(opened, first); err != nil || !bytes.Equal(first, bytes.Repeat([]byte{'x'}, len(first))) {
		t.Fatalf("read staged request bytes=%q err=%v", first, err)
	}

	overLimit := httptest.NewRequest(http.MethodPost, "/v1/vulnerability-scans", strings.NewReader("12345"))
	if _, cleanup, err := streamRequestPayload(overLimit, 4); !errors.Is(err, app.ErrValidation) {
		cleanup()
		t.Fatalf("over-limit stream error=%v, want validation", err)
	}
}

func TestVulnerabilityScanStreamsPastSmallJSONLimit(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "stream-product", map[string]any{"name": "Streaming", "slug": "streaming"}, http.StatusCreated)
	releaseBody := postJSON(t, server, secret, "/v1/releases", "stream-release", map[string]any{"product_id": dataField(t, productBody, "id"), "version": "1.0.0"}, http.StatusCreated)
	body := strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1) + `{"scanner":"stream","target_ref":"pkg:oci/stream","release_id":"` + dataField(t, releaseBody, "id") + `","findings":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/vulnerability-scans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "streamed-vulnerability-scan")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("streamed upload status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNativeDocumentMediaTypesRequireExplicitMetadataHeaders(t *testing.T) {
	server, secret := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(`{"bomFormat":"CycloneDX","components":[]}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
	req.Header.Set("Idempotency-Key", "missing-release-metadata")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing stream metadata status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNativeCycloneDXSBOMStreamsPastSmallJSONLimit(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "native-sbom-product", map[string]any{"name": "Native SBOM", "slug": "native-sbom"}, http.StatusCreated)
	releaseBody := postJSON(t, server, secret, "/v1/releases", "native-sbom-release", map[string]any{"product_id": dataField(t, productBody, "id"), "version": "1.0.0"}, http.StatusCreated)
	body := strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1) + `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
	req.Header.Set("X-Evydence-Release-ID", dataField(t, releaseBody, "id"))
	req.Header.Set("Idempotency-Key", "native-streamed-sbom")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("native streamed SBOM status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNativeCycloneDXSBOMIdempotencyIncludesReleaseHeader(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "native-idempotency-product", map[string]any{"name": "Native idempotency", "slug": "native-idempotency"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	firstReleaseBody := postJSON(t, server, secret, "/v1/releases", "native-idempotency-release-a", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated)
	secondReleaseBody := postJSON(t, server, secret, "/v1/releases", "native-idempotency-release-b", map[string]any{"product_id": productID, "version": "2.0.0"}, http.StatusCreated)
	body := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	send := func(releaseID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
		req.Header.Set("X-Evydence-Release-ID", releaseID)
		req.Header.Set("Idempotency-Key", "native-idempotency-release-header")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := send(dataField(t, firstReleaseBody, "id")); rec.Code != http.StatusCreated {
		t.Fatalf("first upload status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := send(dataField(t, secondReleaseBody, "id")); rec.Code != http.StatusConflict {
		t.Fatalf("changed release header status=%d body=%s, want conflict", rec.Code, rec.Body.String())
	}
}

func TestNativeStreamedUploadReplaysLegacyBodyOnlyFingerprint(t *testing.T) {
	server, secret := testServer(t)
	actor, err := legacyFixtureLedger(server).Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	product, err := legacyFixtureLedger(server).CreateProduct(t.Context(), actor, "Legacy replay", "legacy-replay")
	if err != nil {
		t.Fatal(err)
	}
	release, err := legacyFixtureLedger(server).CreateRelease(t.Context(), actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	sum := sha256.Sum256(body)
	bodyDigest := "sha256:" + hex.EncodeToString(sum[:])
	const key = "legacy-native-streamed-replay"
	legacyResponse := map[string]any{"legacy_replay": true, "id": "sbom_legacy", "tenant_id": actor.TenantID, "release_id": release.ID, "artifact_id": "", "format": "cyclonedx"}
	status, _, err := legacyFixtureLedger(server).WithIdempotencyRequestHash(
		t.Context(), actor, http.MethodPost, "/v1/sboms", key, bodyDigest,
		func(context.Context, *app.Ledger) (int, any, error) {
			return http.StatusCreated, legacyResponse, nil
		},
	)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("seed legacy idempotency record: status=%d err=%v", status, err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
	req.Header.Set("X-Evydence-Release-ID", release.ID)
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"legacy_replay":true`) || !strings.Contains(rec.Body.String(), `"id":"sbom_legacy"`) {
		t.Fatalf("legacy retry status=%d body=%s", rec.Code, rec.Body.String())
	}
	other, err := legacyFixtureLedger(server).CreateRelease(t.Context(), actor, product.ID, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/sboms", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
	req.Header.Set("X-Evydence-Release-ID", other.ID)
	req.Header.Set("Idempotency-Key", key)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "sbom_legacy") {
		t.Fatal("body-only replay exposed mismatched release metadata", rec.Code, rec.Body.String())
	}
}

func TestReadDerivedDiffRoutesPreserveReadOnlyScope(t *testing.T) {
	server, _ := testServer(t)
	want := map[string]bool{
		"/v1/sbom-diffs":    false,
		"/v1/openapi-diffs": false,
	}
	for _, route := range server.evidenceRiskPolicyRoutes() {
		if _, tracked := want[route.path]; !tracked {
			continue
		}
		want[route.path] = true
		if len(route.op.Scopes) != 1 || route.op.Scopes[0] != app.ScopeEvidenceRead {
			t.Errorf("%s scopes = %v, want [%s]", route.path, route.op.Scopes, app.ScopeEvidenceRead)
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("missing route %s", path)
		}
	}
}

func TestStreamedRequestFingerprintCoversSemanticHeadersCanonically(t *testing.T) {
	t.Parallel()
	bodyDigest := "sha256:" + strings.Repeat("a", 64)
	base := map[string]string{
		"artifact_id": "art_1", "media_type": "application/vnd.oai.openapi+json",
		"product_id": "prod_1", "release_id": "rel_1", "version": "1.0.0",
	}
	want := streamedRequestFingerprint(bodyDigest, base)
	reordered := map[string]string{
		"version": "1.0.0", "release_id": "rel_1", "product_id": "prod_1",
		"media_type": "application/vnd.oai.openapi+json", "artifact_id": "art_1",
	}
	if got := streamedRequestFingerprint(bodyDigest, reordered); got != want {
		t.Fatalf("field ordering changed fingerprint: %q / %q", got, want)
	}
	for _, field := range []string{"artifact_id", "media_type", "product_id", "release_id", "version"} {
		changed := make(map[string]string, len(base))
		for key, value := range base {
			changed[key] = value
		}
		changed[field] += "_changed"
		if got := streamedRequestFingerprint(bodyDigest, changed); got == want {
			t.Fatalf("changing %s did not change fingerprint", field)
		}
	}
}

type repeatingByteReader struct {
	remaining int64
	value     byte
	maxRead   int
}

func (r *repeatingByteReader) Read(dst []byte) (int, error) {
	if len(dst) > r.maxRead {
		r.maxRead = len(dst)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(dst)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for index := 0; index < n; index++ {
		dst[index] = r.value
	}
	r.remaining -= int64(n)
	return n, nil
}
