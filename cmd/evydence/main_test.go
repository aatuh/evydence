package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCleanOperatorPathRejectsNUL(t *testing.T) {
	if _, err := cleanOperatorPath("attestation.json\x00"); err == nil {
		t.Fatal("expected NUL path rejection")
	}
}

func TestGitHubActionsUploadBuildRequiresGitHubMetadata(t *testing.T) {
	t.Setenv("EVYDENCE_API_URL", "http://127.0.0.1")
	t.Setenv("EVYDENCE_API_KEY", "evy_secret")
	err := uploadGitHubActionsBuild(t.Context(), http.DefaultClient, []string{"--project-id", "proj_1", "--release-id", "rel_1"})
	if err == nil || !strings.Contains(err.Error(), "GITHUB_RUN_ID") {
		t.Fatalf("err=%v, want missing GitHub metadata error", err)
	}
}

func TestGitHubActionsUploadBuildPostsBuildAndAttestationSafely(t *testing.T) {
	attestationFile, err := os.CreateTemp(t.TempDir(), "attestation-*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if _, err := attestationFile.WriteString(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"abc"}]}`); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	if err := attestationFile.Close(); err != nil {
		t.Fatalf("close attestation: %v", err)
	}
	t.Setenv("EVYDENCE_API_KEY", "evy_secret")
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	t.Setenv("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
	t.Setenv("GITHUB_REPOSITORY", "aatuh/evydence")
	t.Setenv("GITHUB_WORKFLOW_REF", "aatuh/evydence/.github/workflows/release.yml@refs/heads/main")
	t.Setenv("GITHUB_JOB", "build")
	t.Setenv("GITHUB_ACTOR", "aatu")
	t.Setenv("GITHUB_REF", "refs/heads/main")

	var sawBuild, sawAttestation bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer evy_secret" {
			t.Fatalf("authorization header=%q", got)
		}
		switch r.URL.Path {
		case "/v1/builds":
			sawBuild = true
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode build: %v", err)
			}
			if payload["collector_id"] != nil {
				t.Fatalf("CLI must not submit collector_id: %#v", payload)
			}
			if payload["repository"] != "aatuh/evydence" || payload["run_id"] != "12345" || payload["oidc_subject"] != "" {
				t.Fatalf("unexpected build payload: %#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"build_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/builds/build_1/attestations":
			sawAttestation = true
			if r.Header.Get("Idempotency-Key") != "github-actions-attestation-build_1" {
				t.Fatalf("unexpected attestation idempotency key: %s", r.Header.Get("Idempotency-Key"))
			}
			_, _ = w.Write([]byte(`{"data":{"id":"att_1"},"meta":{"api_version":"v1"}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	err = uploadGitHubActionsBuild(t.Context(), server.Client(), []string{
		"--url", server.URL,
		"--api-key", "evy_secret",
		"--project-id", "proj_1",
		"--release-id", "rel_1",
		"--artifact-id", "art_1",
		"--artifact-digest", "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		"--attestation-path", attestationFile.Name(),
		"--started-at", "2026-05-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !sawBuild || !sawAttestation {
		t.Fatalf("sawBuild=%v sawAttestation=%v", sawBuild, sawAttestation)
	}
}
