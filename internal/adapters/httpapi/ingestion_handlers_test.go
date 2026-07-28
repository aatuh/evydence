package httpapi

import (
	"bytes"
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
