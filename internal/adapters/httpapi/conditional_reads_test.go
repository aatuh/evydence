package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConditionalReadWriterPassesThroughOversizedResponse(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &conditionalReadWriter{ResponseWriter: recorder}
	writer.WriteHeader(http.StatusAccepted)
	writer.WriteHeader(http.StatusOK)
	payload := strings.Repeat("x", maxConditionalReadBodyBytes+1)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatalf("Write oversized body: %v", err)
	}
	if !writer.passthrough || recorder.Code != http.StatusAccepted || recorder.Body.Len() != len(payload) {
		t.Fatalf("oversized response passthrough=%t status=%d bytes=%d", writer.passthrough, recorder.Code, recorder.Body.Len())
	}
	if _, err := writer.Write([]byte("tail")); err != nil {
		t.Fatalf("Write passthrough tail: %v", err)
	}
	if !strings.HasSuffix(recorder.Body.String(), "tail") {
		t.Fatalf("passthrough body lost tail: %d bytes", recorder.Body.Len())
	}
}

func TestConditionalReadETagHelpersValidateHeadersAndRevision(t *testing.T) {
	if got := resourceETag([]byte(`{"data":{"revision":4}}`)); got != `"4"` {
		t.Fatalf("revision ETag = %q, want \"4\"", got)
	}
	if got := resourceETag([]byte(`{"data":{"revision":"04"}}`)); got == `"04"` || got == "" {
		t.Fatalf("invalid revision ETag = %q, want digest", got)
	}
	headers := make(http.Header)
	headers.Set("Vary", "Accept, Authorization")
	setPrivateETagHeaders(headers, `"etag"`)
	setPrivateETagHeaders(headers, `"etag"`)
	if got := headers.Get("ETag"); got != `"etag"` {
		t.Fatalf("ETag = %q", got)
	}
	if got := headers.Get("Cache-Control"); got != "private, max-age=0, must-revalidate" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := headers.Values("Vary"); len(got) != 1 {
		t.Fatalf("Vary values = %#v, want Authorization only once", got)
	}

	for _, tc := range []struct {
		name   string
		header string
		match  bool
		valid  bool
	}{
		{name: "weak and strong", header: `W/"one", "etag"`, match: true, valid: true},
		{name: "wildcard", header: "*", match: true, valid: true},
		{name: "empty", header: "", valid: false},
		{name: "wildcard mixed", header: `*, "etag"`, valid: false},
		{name: "unterminated", header: `"etag`, valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/products/product_1", nil)
			r.Header.Set("If-None-Match", tc.header)
			parsed, err := parseIfNoneMatch(r)
			if (err == nil) != tc.valid {
				t.Fatalf("parseIfNoneMatch(%q) err=%v valid=%t", tc.header, err, tc.valid)
			}
			if err == nil && parsed.matches(`"etag"`) != tc.match {
				t.Fatalf("matches = %t, want %t", parsed.matches(`"etag"`), tc.match)
			}
		})
	}
}
