package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func cleanCLIEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "ENV" || name == "CI" || strings.HasPrefix(name, "EVYDENCE_") || strings.HasPrefix(name, "GITHUB_") {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestOnlineCLIRejectsConfigurationBeforeEffects(t *testing.T) {
	for _, route := range [][]string{{"github-actions", "upload-build"}, {"ci", "preflight"}, {"import-bundle", "upload"}, {"upload", "manifest"}, {"release", "upload-evidence"}} {
		t.Run(strings.Join(route, "-"), func(t *testing.T) {
			cleanCLIEnvironment(t)
			t.Setenv("ENV", "production")
			t.Setenv("EVYDENCE_PRIVATE_UNKNOWN_OPTION", "PRIVATE_CONFIGURATION")
			// A nonexistent payload must not be read before complete preflight.
			args := append(append([]string{}, route...), "--url", "https://example.test", "--api-key", "PRIVATE_KEY")
			switch route[0] {
			case "github-actions":
				args = append(args, "--project-id", "project", "--release-id", "release")
			case "ci":
				args = append(args, "--product-id", "product", "--project-id", "project", "--release-id", "release", "--artifact-id", "artifact", "--manifest", "PRIVATE_MISSING_PAYLOAD")
			case "import-bundle":
				args = append(args, "--path", "PRIVATE_MISSING_PAYLOAD")
			case "upload":
				args = append(args, "--manifest", "PRIVATE_MISSING_PAYLOAD")
			case "release":
				args = append(args, "--release-id", "release", "--sbom", "PRIVATE_MISSING_PAYLOAD")
			}
			err := run(args)
			if err == nil || !strings.Contains(err.Error(), "configuration is invalid") || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("startup did not reject with a fixed diagnostic; error withheld")
			}
		})
	}
}

func TestCLIAPIKeyFileAndFlagPrecedence(t *testing.T) {
	cleanCLIEnvironment(t)
	dir := t.TempDir()
	key := writeTestFile(t, filepath.Join(dir, "key"), []byte("PRIVATE_FILE_KEY\n"))
	payload := writeTestFile(t, filepath.Join(dir, "bundle.json"), []byte(`{"manifest":{}}`))
	t.Setenv("EVYDENCE_API_KEY_FILE", key)
	t.Setenv("EVYDENCE_API_URL", "PRIVATE_INVALID_URL")
	t.Setenv("EVYDENCE_BUILD_STARTED_AT", "PRIVATE_UNUSED_BUILD_TIME")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/evidence-bundles/import" || r.Header.Get("Authorization") != "Bearer PRIVATE_FILE_KEY" {
			t.Error("request changed credential, method or path")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":"import"}}`)
	}))
	defer server.Close()
	out, err := captureStdout(t, func() error { return run([]string{"import-bundle", "upload", "--url", server.URL, "--path", payload}) })
	if err != nil || calls.Load() != 1 || strings.Contains(out, "PRIVATE") {
		t.Fatal("resolved file credential or explicit URL precedence failed; output withheld")
	}
	calls.Store(0)
	err = run([]string{"import-bundle", "upload", "--url", server.URL, "--api-key", "PRIVATE_FLAG_KEY", "--path", payload})
	if err == nil || calls.Load() != 0 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("flag and secret-file conflict did not fail before a request")
	}
}

func TestCLIGitHubRunAttemptRejectsMalformedValuesBeforeRequest(t *testing.T) {
	cleanCLIEnvironment(t)
	for name, value := range map[string]string{"GITHUB_RUN_ID": "42", "GITHUB_SHA": "commit", "GITHUB_REPOSITORY": "owner/repo", "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/heads/main"} {
		t.Setenv(name, value)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"data":{"id":"build"}}`)
	}))
	defer server.Close()
	for _, raw := range []string{"0", "-1", "2PRIVATE_INVALID", "2147483648"} {
		t.Run(raw, func(t *testing.T) {
			calls.Store(0)
			t.Setenv("GITHUB_RUN_ATTEMPT", raw)
			out, err := captureStdout(t, func() error {
				return run([]string{"github-actions", "upload-build", "--url", server.URL, "--api-key", "PRIVATE_KEY", "--project-id", "project", "--release-id", "release"})
			})
			if err == nil || calls.Load() != 0 || strings.Contains(out, "PRIVATE") || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("malformed run attempt was not rejected before network; output withheld")
			}
		})
	}
}

func TestCLIHelpAndOfflineIgnoreUnusedRuntimeConfiguration(t *testing.T) {
	cleanCLIEnvironment(t)
	routes := [][]string{{"import-bundle", "upload", "--help"}, {"github-actions", "upload-build", "--help"}, {"ci", "preflight", "--help"}, {"release", "upload-evidence", "--help"}, {"upload", "manifest", "--help"}}
	baseline := make([]string, len(routes))
	for i, route := range routes {
		if err := run(route); err != nil {
			baseline[i] = err.Error()
		} else {
			t.Fatal("help lost its usage contract")
		}
	}

	t.Setenv("ENV", "production")
	t.Setenv("EVYDENCE_PRIVATE_UNKNOWN_OPTION", "PRIVATE_UNUSED")
	t.Setenv("EVYDENCE_API_KEY_FILE", "/PRIVATE_MISSING_SECRET")
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_INVALID_DATABASE")
	t.Setenv("EVYDENCE_LOG_FORMAT", "PRIVATE_INVALID_FORMAT")
	path := writeTestFile(t, filepath.Join(t.TempDir(), "payload"), []byte("offline"))
	out, err := captureStdout(t, func() error { return run([]string{"hash", path}) })
	if err != nil || !bytes.HasPrefix([]byte(out), []byte("sha256:")) {
		t.Fatal("offline hash acquired unused runtime dependencies")
	}
	for i, route := range routes {
		if err := run(route); err == nil || err.Error() != baseline[i] {
			t.Fatal("help acquired unused runtime dependencies")
		}
	}
}

func captureCLIInput(t *testing.T) cliInput {
	t.Helper()
	environment, err := config.Capture(os.Environ())
	if err != nil {
		t.Fatal("capture test CLI environment")
	}
	return cliInput{environment: environment}
}

func TestCLIStartupRejectsBeforeOperationAndRedactsDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		entries    []string
		captureErr error
		flags      []string
	}{
		{name: "capture", captureErr: errors.New("PRIVATE_CAPTURE_ERROR")},
		{name: "log-format", entries: []string{"EVYDENCE_LOG_FORMAT=PRIVATE_FORMAT"}},
		{name: "endpoint", entries: []string{"EVYDENCE_API_URL=https://PRIVATE_USER:PRIVATE_PASSWORD@example.test"}},
		{name: "credential-file", entries: []string{"EVYDENCE_API_KEY_FILE=/PRIVATE_MISSING_FILE"}},
		{name: "source-conflict", entries: []string{"EVYDENCE_API_KEY_FILE=/PRIVATE_MISSING_FILE"}, flags: []string{"--api-key", "PRIVATE_FLAG_KEY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environment, err := config.Capture(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			fs := flag.NewFlagSet("fixture", flag.ContinueOnError)
			registerCLIConnectionFlags(fs)
			if err := fs.Parse(tc.flags); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			called := false
			err = runConfiguredCLI(t.Context(), cliInput{environment: environment, captureErr: tc.captureErr}, &output, fs, config.CLIUpload, func(context.Context, config.CLISettings) error { called = true; return nil })
			if !errors.Is(err, errCLIConfiguration) || called || strings.Contains(output.String(), "PRIVATE") {
				t.Fatal("startup callback ran or raw configuration escaped fixed diagnostics")
			}
		})
	}
}

func TestCLIHelpIgnoresCaptureFailure(t *testing.T) {
	for _, command := range []func(context.Context, *http.Client, cliInput, []string) error{uploadGitHubActionsBuild, ciPreflight, uploadEvidenceBundleImport, uploadManifestRequests, uploadReleaseEvidence} {
		baseline := command(t.Context(), http.DefaultClient, cliInput{}, []string{"--help"})
		got := command(t.Context(), http.DefaultClient, cliInput{captureErr: errors.New("PRIVATE_CAPTURE_FAILURE")}, []string{"--help"})
		if baseline == nil || got == nil || baseline.Error() != got.Error() {
			t.Fatal("help depends on the environment snapshot")
		}
	}
}
