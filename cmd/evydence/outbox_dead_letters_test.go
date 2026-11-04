package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOutboxCLIDeadLettersPreserveCursorAndSafeMetadata(t *testing.T) {
	cleanCLIEnvironment(t)
	t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/admin/outbox/dead-letters" || r.URL.Query().Get("page_size") != "2" || r.URL.Query().Get("direction") != "desc" || r.URL.Query().Get("cursor") != "previous.cursor" || r.Header.Get("Authorization") != "Bearer PRIVATE_OPERATOR_KEY" || r.Header.Get("Idempotency-Key") != "" {
			t.Error("dead-letter CLI changed the read-only endpoint, credential or continuation")
		}
		_, _ = fmt.Fprint(w, `{"data":[{"id":"job_b","kind":"parse_sbom","status":"dead_letter","attempts":1,"max_attempts":5,"failure_class":"permanent","failure_code":"invalid_document","created_at":"2026-11-04T09:00:00Z","terminal_at":"2026-11-04T10:00:00Z","payload":"PRIVATE_PAYLOAD"},{"id":"job_a","kind":"parse_sbom","status":"dead_letter","attempts":2,"max_attempts":5,"failure_class":"poisoned","failure_code":"digest_mismatch","created_at":"2026-11-04T09:00:00Z","terminal_at":"2026-11-04T10:00:00Z"}],"meta":{"api_version":"v1","page_size":2,"sort":"id","direction":"desc","next_cursor":"next.cursor","private":"PRIVATE_METADATA"}}`)
	}))
	defer server.Close()
	output, err := captureStdout(t, func() error {
		return run([]string{"outbox", "dead-letters", "--url", server.URL, "--page-size", "2", "--direction", "desc", "--cursor", "previous.cursor"})
	})
	if err != nil || calls.Load() != 1 || strings.Contains(output, "PRIVATE") || !strings.Contains(output, `"next_cursor":"next.cursor"`) || !strings.Contains(output, `"id":"job_a"`) {
		t.Fatal("dead-letter CLI failed or exposed unselected fields", err)
	}
}

func TestOutboxCLIDeadLettersRejectUntrustedPageFeedback(t *testing.T) {
	for _, body := range []string{
		`{"data":null,"meta":{"api_version":"v1","page_size":50,"sort":"id","direction":"asc"}}`,
		`{"data":[]}`,
		`{"data":[],"meta":{"api_version":"v1","page_size":50,"sort":"created_at","direction":"asc"}}`,
		`{"data":[],"meta":{"api_version":"v1","page_size":51,"sort":"id","direction":"asc"}}`,
		`{"data":[],"meta":{"api_version":"v1","page_size":50,"sort":"id","direction":"desc"}}`,
		`{"data":[],"meta":{"api_version":"v1","page_size":50,"sort":"id","direction":"asc","next_cursor":"unexpected.cursor"}}`,
		`{"data":[],"data":[],"meta":{"api_version":"v1","page_size":50,"sort":"id","direction":"asc"}}`,
		`{"data":[{"id":"job_a","kind":"parse_sbom","status":"dead_letter","attempts":1,"max_attempts":5,"failure_class":"permanent","failure_code":"PRIVATE error","created_at":"2026-11-04T09:00:00Z","terminal_at":"2026-11-04T10:00:00Z"}],"meta":{"api_version":"v1","page_size":50,"sort":"id","direction":"asc"}}`,
	} {
		cleanCLIEnvironment(t)
		t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = fmt.Fprint(w, body)
		}))
		output, err := captureStdout(t, func() error { return run([]string{"outbox", "dead-letters", "--url", server.URL}) })
		server.Close()
		if err == nil || output != "" || strings.Contains(err.Error(), "PRIVATE") || calls.Load() != 1 {
			t.Fatal("unsafe dead-letter feedback reached output or hid a missing request")
		}
	}
}
