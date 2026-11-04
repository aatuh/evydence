package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestOutboxCLIBacklogAndReplayUseExistingAdminAPI(t *testing.T) {
	for _, command := range []string{"backlog", "replay"} {
		t.Run(command, func(t *testing.T) {
			cleanCLIEnvironment(t)
			t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
			t.Setenv("EVYDENCE_BUILD_STARTED_AT", "PRIVATE_UNUSED_BUILD_TIME")
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer PRIVATE_OPERATOR_KEY" {
					t.Error("operator credential was not preserved")
				}
				w.Header().Set("Content-Type", "application/json")
				if command == "backlog" {
					if r.Method != "GET" || r.URL.RequestURI() != "/v1/admin/outbox" {
						t.Error("backlog request changed the admin API contract")
					}
					_, _ = fmt.Fprint(w, `{"data":{"pending_jobs":2,"running_jobs":1,"terminal_jobs":3,"oldest_pending_created_at":"2026-11-04T10:00:00Z","payload":"PRIVATE_PAYLOAD"}}`)
					return
				}
				if r.Method != "POST" || r.URL.RequestURI() != "/v1/admin/outbox/job_1/replay" || r.Header.Get("Idempotency-Key") != "operation-1" {
					t.Error("replay did not preserve the explicit job and operation identity")
				}
				_, _ = fmt.Fprint(w, `{"data":{"job_id":"job_1","status":"queued","replayed_at":"2026-11-04T10:00:00Z","payload":"PRIVATE_PAYLOAD"}}`)
			}))
			defer server.Close()
			args := []string{"outbox", command, "--url", server.URL}
			if command == "replay" {
				args = append(args, "--job-id", "job_1", "--idempotency-key", "operation-1")
			}
			attempts := 1
			if command == "replay" {
				attempts = 2
			}
			for range attempts {
				output, err := captureStdout(t, func() error { return run(args) })
				if err != nil || strings.Contains(output, "PRIVATE") || !strings.Contains(output, `"data"`) {
					t.Fatal("outbox command failed or exposed unselected server fields", err)
				}
			}
			if int(calls.Load()) != attempts {
				t.Fatal("outbox command changed request/retry count")
			}
		})
	}
}

func TestOutboxCLIRejectsInvalidArgumentsBeforeNetwork(t *testing.T) {
	cleanCLIEnvironment(t)
	t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	for _, args := range [][]string{
		{"backlog", "extra"}, {"backlog", "--job-id", "job_1"},
		{"replay"}, {"replay", "--job-id", "job_1"},
		{"replay", "--job-id", "../PRIVATE_OTHER", "--idempotency-key", "operation-1"},
		{"replay", "--job-id", "job_1", "--idempotency-key", "PRIVATE\nKEY"},
		{"replay", "--job-id", "job_1", "--idempotency-key", strings.Repeat("x", 129)},
		{"replay", "--job-id", "job_1", "--job-id", "job_2", "--idempotency-key", "operation-1"},
		{"replay", "--job-id", "job_1", "--idempotency-key", "one", "--idempotency-key", "two"},
	} {
		command := append([]string{"outbox", args[0], "--url", server.URL}, args[1:]...)
		output, err := captureStdout(t, func() error { return run(command) })
		if err == nil || strings.Contains(output+err.Error(), "PRIVATE") || calls.Load() != 0 {
			t.Fatal("invalid operator input reached a request or exposed its contents")
		}
	}
}

func TestOutboxCLIRejectsUntrustedResponseWithoutExposingDetails(t *testing.T) {
	for _, body := range []string{
		`{"data":{"pending_jobs":-1,"running_jobs":0,"terminal_jobs":0}}`,
		`{"data":{"pending_jobs":0,"running_jobs":0}}`,
		`{"data":{"pending_jobs":1,"running_jobs":0,"terminal_jobs":0}}`,
		`{"data":{"pending_jobs":0,"pending_jobs":1,"running_jobs":0,"terminal_jobs":0}}`,
		`PRIVATE_NOT_JSON`,
	} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			cleanCLIEnvironment(t)
			t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, body) }))
			defer server.Close()
			output, err := captureStdout(t, func() error { return run([]string{"outbox", "backlog", "--url", server.URL}) })
			if err == nil || strings.Contains(output+err.Error(), "PRIVATE") || output != "" {
				t.Fatal("invalid operational response was accepted or exposed")
			}
		})
	}
}

func TestOutboxCLIRejectsRedirectsAndHidesServerFailureDetails(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			cleanCLIEnvironment(t)
			t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
			var targetCalls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"detail":"PRIVATE_SERVER_ERROR","code":"PRIVATE_CODE"}`)
			}))
			defer server.Close()
			output, err := captureStdout(t, func() error { return run([]string{"outbox", "backlog", "--url", server.URL}) })
			if err == nil || output != "" || strings.Contains(err.Error(), "PRIVATE") || !strings.Contains(err.Error(), fmt.Sprint(status)) || targetCalls.Load() != 0 {
				t.Fatal("operator request followed a redirect or exposed server details")
			}
		})
	}
}

func TestOutboxCLIHelpDoesNotResolveCredentials(t *testing.T) {
	cleanCLIEnvironment(t)
	t.Setenv("EVYDENCE_API_KEY_FILE", "/PRIVATE_MISSING_KEY")
	for _, command := range []string{"backlog", "replay"} {
		output, err := captureStdout(t, func() error { return run([]string{"outbox", command, "--help"}) })
		if err != nil || !strings.Contains(output, "usage:") || strings.Contains(output, "PRIVATE") {
			t.Fatal("operator help resolved an unused credential source", err)
		}
	}
}

func TestOutboxCLIPreservesCancellationWithoutRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	environment, err := config.Capture([]string{"EVYDENCE_API_URL=" + server.URL, "EVYDENCE_API_KEY=PRIVATE_OPERATOR_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output, diagnostics bytes.Buffer
	err = runOutboxCLI(ctx, cliInput{environment: environment}, []string{"backlog"}, &output, &diagnostics)
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 || output.Len() != 0 || strings.Contains(diagnostics.String()+err.Error(), "PRIVATE") {
		t.Fatal("operator cancellation lost context, exposed credentials or reached the network")
	}
}

func TestOutboxCLIRejectsMismatchedReplayFeedback(t *testing.T) {
	for _, body := range []string{
		`{"data":{"job_id":"other","status":"queued","replayed_at":"2026-11-04T10:00:00Z"}}`,
		`{"data":{"job_id":"job_1","status":"dead_letter","replayed_at":"2026-11-04T10:00:00Z"}}`,
		`{"data":{"job_id":"job_1","status":"queued"}}`,
	} {
		cleanCLIEnvironment(t)
		t.Setenv("EVYDENCE_API_KEY", "PRIVATE_OPERATOR_KEY")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, body) }))
		output, err := captureStdout(t, func() error {
			return run([]string{"outbox", "replay", "--url", server.URL, "--job-id", "job_1", "--idempotency-key", "operation-1"})
		})
		server.Close()
		if err == nil || output != "" {
			t.Fatal("operator replay accepted mismatched or incomplete feedback")
		}
	}
}

func TestOutboxCLICredentialFileAndFlagConflict(t *testing.T) {
	cleanCLIEnvironment(t)
	key := writeTestFile(t, filepath.Join(t.TempDir(), "key"), []byte("PRIVATE_FILE_KEY\n"))
	t.Setenv("EVYDENCE_API_KEY_FILE", key)
	t.Setenv("EVYDENCE_API_URL", "PRIVATE_UNUSED_URL")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer PRIVATE_FILE_KEY" {
			t.Error("outbox credential file was not resolved")
		}
		_, _ = fmt.Fprint(w, `{"data":{"pending_jobs":0,"running_jobs":0,"terminal_jobs":0}}`)
	}))
	defer server.Close()
	output, err := captureStdout(t, func() error { return run([]string{"outbox", "backlog", "--url", server.URL}) })
	if err != nil || calls.Load() != 1 || strings.Contains(output, "PRIVATE") {
		t.Fatal("outbox file credential or explicit URL precedence failed", err)
	}
	_, err = captureStdout(t, func() error {
		return run([]string{"outbox", "backlog", "--url", server.URL, "--api-key", "PRIVATE_FLAG_KEY"})
	})
	if err == nil || calls.Load() != 1 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("outbox flag silently replaced an active credential file")
	}
}
