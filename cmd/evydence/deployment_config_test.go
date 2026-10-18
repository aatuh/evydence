//go:build deployment

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
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/deploymentcheck"
)

func TestDeploymentCLIStartup(t *testing.T) {
	for _, mode := range []string{"env", "files"} {
		t.Run(mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, "operator", "cli", mode)
			for _, command := range []config.CLICommand{config.CLIUpload, config.CLIGitHubBuild, config.CLIPreflight} {
				t.Run(fmt.Sprint(command), func(t *testing.T) {
					input := cliInput{environment: fixture.Input(t, nil)}
					t.Setenv("EVYDENCE_API_KEY", "PRIVATE_CHANGED_AFTER_CAPTURE")
					fs := flag.NewFlagSet("deployment", flag.ContinueOnError)
					registerCLIConnectionFlags(fs)
					var output bytes.Buffer
					called := false
					err := runConfiguredCLI(t.Context(), input, &output, fs, command, func(_ context.Context, settings config.CLISettings) error {
						called = true
						if settings.APIKey.Reveal() != fixture.Expected["EVYDENCE_API_KEY"] || settings.APIURL != fixture.Expected["EVYDENCE_API_URL"] {
							t.Fatal("operator CLI input lost its captured credential or endpoint")
						}
						return nil
					})
					if err != nil || !called {
						t.Fatal("operator CLI did not reach a validated operation")
					}
					fixture.CheckDiagnostics(t, output.String(), err)
					for _, overrides := range []map[string]string{
						{"EVYDENCE_PRIVATE_UNKNOWN": "PRIVATE_VALUE"},
						{"EVYDENCE_API_URL": "https://PRIVATE_USER:PRIVATE_PASSWORD@example.test"},
					} {
						output.Reset()
						called = false
						err := runConfiguredCLI(t.Context(), cliInput{environment: fixture.Input(t, overrides)}, &output, fs, command, func(context.Context, config.CLISettings) error { called = true; return nil })
						if !errors.Is(err, errCLIConfiguration) || called {
							t.Fatal("invalid operator CLI input reached an operation")
						}
						fixture.CheckDiagnostics(t, output.String(), err)
					}
					if mode == "files" {
						if err := fs.Parse([]string{"--api-key", "PRIVATE_FLAG_KEY"}); err != nil {
							t.Fatal(err)
						}
						output.Reset()
						called = false
						err := runConfiguredCLI(t.Context(), input, &output, fs, command, func(context.Context, config.CLISettings) error { called = true; return nil })
						if !errors.Is(err, errCLIConfiguration) || called {
							t.Fatal("credential flag/file conflict reached a CLI operation")
						}
						fixture.CheckDiagnostics(t, output.String(), err)
					}
				})
			}
		})
	}
}

func TestDeploymentCLIImportCommand(t *testing.T) {
	for _, mode := range []string{"env", "files"} {
		t.Run(mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, "operator", "cli", mode)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.Method != http.MethodPost || request.URL.Path != "/v1/evidence-bundles/import" || request.Header.Get("Authorization") != "Bearer "+fixture.Expected["EVYDENCE_API_KEY"] {
					t.Error("actual CLI command lost its credential or operation")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"data":{"id":"fixture-import"}}`)
			}))
			defer server.Close()
			fixture.Install(t, os.Environ(), map[string]string{"EVYDENCE_API_URL": server.URL})
			payload := writeTestFile(t, filepath.Join(t.TempDir(), "bundle.json"), []byte(`{"manifest":{}}`))
			output, err := captureStdout(t, func() error { return run([]string{"import-bundle", "upload", "--path", payload}) })
			if err != nil || calls.Load() != 1 {
				t.Fatal("actual CLI command did not complete its authenticated request")
			}
			fixture.CheckDiagnostics(t, output, err)
			calls.Store(0)
			t.Setenv("EVYDENCE_PRIVATE_UNKNOWN", "PRIVATE_VALUE")
			err = run([]string{"import-bundle", "upload", "--path", "/PRIVATE_MISSING_PAYLOAD"})
			if !errors.Is(err, errCLIConfiguration) || calls.Load() != 0 {
				t.Fatal("invalid actual CLI command reached payload/network effects")
			}
			fixture.CheckDiagnostics(t, "", err)
		})
	}
}
