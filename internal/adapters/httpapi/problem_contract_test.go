package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

// TestDocumentedProblemCodesHaveHTTPRouteSerializationCoverage proves every
// generated catalog code at the HTTP boundary, including request IDs and retry
// headers. Production route tests separately cover malformed input, auth,
// rate limiting, readiness, idempotency, and version conflicts.
func TestDocumentedProblemCodesHaveHTTPRouteSerializationCoverage(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"validation", app.ErrValidation},
		{"unauthorized", app.ErrUnauthorized},
		{"forbidden", app.ErrForbidden},
		{"not found", app.ErrNotFound},
		{"version conflict", app.NewVersionConflict(2)},
		{"conflict", app.ErrConflict},
		{"immutable", app.ErrImmutable},
		{"idempotency reused", app.ErrIdempotencyConflict},
		{"idempotency in progress", app.ErrIdempotencyInProgress},
		{"idempotency failed", app.ErrIdempotencyFailed},
		{"cosign unavailable", app.ErrFullVerificationUnavailable},
		{"verification failed", app.ErrVerificationFailed},
		{"rate limited", app.ErrRateLimited},
		{"signing provider", app.ErrRetryableSigning},
		{"dependency", app.ErrDependencyUnavailable},
		{"internal", errors.New("postgres://user:super-secret@db.internal failed")},
	}
	covered := map[app.ErrorCode]struct{}{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expected := app.DescribeProblem(testCase.err)
			covered[expected.Code] = struct{}{}
			handler := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeProblem(w, r, testCase.err)
			}))
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/v1/problem-contract", nil)
			request.Header.Set(requestIDHeader, "req-problem-contract")
			handler.ServeHTTP(recorder, request)
			if recorder.Code != expected.Status {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, expected.Status, recorder.Body.String())
			}
			var body struct {
				Code       app.ErrorCode  `json:"code"`
				RequestID  string         `json:"request_id"`
				Retryable  bool           `json:"retryable"`
				RetryClass app.RetryClass `json:"retry_class"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode problem: %v body=%s", err, recorder.Body.String())
			}
			if body.Code != expected.Code || body.RequestID != "req-problem-contract" || body.Retryable != expected.Retryable || body.RetryClass != expected.RetryClass {
				t.Fatalf("problem body=%#v expected=%#v", body, expected)
			}
			if expected.RetryAfterSeconds > 0 && recorder.Header().Get("Retry-After") == "" {
				t.Fatalf("retrying code %q has no Retry-After header", expected.Code)
			}
			if expected.Code == app.CodeInternalError && (strings.Contains(recorder.Body.String(), "super-secret") || strings.Contains(recorder.Body.String(), "db.internal")) {
				t.Fatalf("internal problem leaked cause: %s", recorder.Body.String())
			}
		})
	}
	for _, definition := range app.ErrorCatalog() {
		if _, ok := covered[definition.Code]; !ok {
			t.Fatalf("documented code %q has no HTTP route serialization test", definition.Code)
		}
	}
}
