package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "hash":
		if len(args) != 2 {
			return usage()
		}
		digest, err := hashFile(args[1])
		if err != nil {
			return err
		}
		fmt.Println(digest)
		return nil
	case "verify-manifest":
		if len(args) != 4 || args[2] != "--hash" {
			return usage()
		}
		return verifyManifest(args[1], args[3])
	case "github-actions":
		if len(args) < 2 || args[1] != "upload-build" {
			return usage()
		}
		return uploadGitHubActionsBuild(context.Background(), http.DefaultClient, args[2:])
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("usage: evydence hash <file> | evydence verify-manifest <manifest.json> --hash sha256:<hex> | evydence github-actions upload-build --url <api-url> --api-key <key> --project-id <id> --release-id <id> [--artifact-id <id> --artifact-digest sha256:<hex> --attestation-path <file>]")
}

func hashFile(path string) (string, error) {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return "", err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified file and does not use elevated privileges.
	file, err := os.Open(cleaned)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func verifyManifest(path, expected string) error {
	expected = strings.TrimSpace(expected)
	if !strings.HasPrefix(expected, "sha256:") {
		return errors.New("expected hash must use sha256:<hex>")
	}
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified manifest and does not use elevated privileges.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return fmt.Errorf("manifest is not JSON: %w", err)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonical)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != expected {
		return fmt.Errorf("manifest hash mismatch: got %s want %s", got, expected)
	}
	fmt.Println("manifest hash verified")
	return nil
}

func cleanOperatorPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("file path is required")
	}
	if strings.Contains(path, "\x00") {
		return "", errors.New("file path contains a NUL byte")
	}
	return filepath.Clean(path), nil
}

func uploadGitHubActionsBuild(ctx context.Context, client *http.Client, args []string) error {
	fs := flag.NewFlagSet("github-actions upload-build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		apiURL          = fs.String("url", strings.TrimSpace(os.Getenv("EVYDENCE_API_URL")), "Evydence API URL")
		apiKey          = fs.String("api-key", strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY")), "Evydence API key")
		projectID       = fs.String("project-id", "", "Evydence project ID")
		releaseID       = fs.String("release-id", "", "Evydence release ID")
		artifactID      = fs.String("artifact-id", "", "Evydence artifact ID")
		artifactDigest  = fs.String("artifact-digest", "", "artifact digest")
		attestationPath = fs.String("attestation-path", "", "DSSE attestation JSON path")
		status          = fs.String("status", envDefault("EVYDENCE_BUILD_STATUS", "passed"), "build status")
		startedAt       = fs.String("started-at", envDefault("EVYDENCE_BUILD_STARTED_AT", time.Now().UTC().Format(time.RFC3339)), "build start time")
		finishedAt      = fs.String("finished-at", strings.TrimSpace(os.Getenv("EVYDENCE_BUILD_FINISHED_AT")), "build finish time")
		parametersHash  = fs.String("parameters-hash", "", "build parameters hash")
		environmentHash = fs.String("environment-hash", "", "build environment hash")
		oidcSubject     = fs.String("oidc-subject", strings.TrimSpace(os.Getenv("EVYDENCE_GITHUB_OIDC_SUBJECT")), "captured GitHub OIDC subject")
	)
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*apiURL) == "" || strings.TrimSpace(*apiKey) == "" || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*releaseID) == "" {
		return usage()
	}
	if (*artifactID == "") != (*artifactDigest == "") {
		return errors.New("--artifact-id and --artifact-digest must be provided together")
	}
	started, err := time.Parse(time.RFC3339, strings.TrimSpace(*startedAt))
	if err != nil {
		return errors.New("--started-at must use RFC3339")
	}
	var finished *time.Time
	if strings.TrimSpace(*finishedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*finishedAt))
		if err != nil {
			return errors.New("--finished-at must use RFC3339")
		}
		finished = &parsed
	}
	outputs := []map[string]string{}
	if strings.TrimSpace(*artifactID) != "" {
		outputs = append(outputs, map[string]string{"artifact_id": strings.TrimSpace(*artifactID), "digest": strings.TrimSpace(*artifactDigest)})
	}
	runID := envRequired("GITHUB_RUN_ID")
	runAttempt := envDefault("GITHUB_RUN_ATTEMPT", "1")
	commitSHA := envRequired("GITHUB_SHA")
	repository := envRequired("GITHUB_REPOSITORY")
	workflowRef := envRequired("GITHUB_WORKFLOW_REF")
	if runID == "" || commitSHA == "" || repository == "" || workflowRef == "" {
		return errors.New("GITHUB_RUN_ID, GITHUB_SHA, GITHUB_REPOSITORY, and GITHUB_WORKFLOW_REF are required")
	}
	payload := map[string]any{
		"project_id":       strings.TrimSpace(*projectID),
		"release_id":       strings.TrimSpace(*releaseID),
		"provider":         "github_actions",
		"commit_sha":       commitSHA,
		"repository":       repository,
		"workflow_ref":     workflowRef,
		"run_id":           runID,
		"run_attempt":      atoiDefault(runAttempt, 1),
		"job_id":           strings.TrimSpace(os.Getenv("GITHUB_JOB")),
		"actor":            strings.TrimSpace(os.Getenv("GITHUB_ACTOR")),
		"ref":              strings.TrimSpace(os.Getenv("GITHUB_REF")),
		"oidc_subject":     strings.TrimSpace(*oidcSubject),
		"status":           strings.TrimSpace(*status),
		"started_at":       started.UTC().Format(time.RFC3339),
		"finished_at":      finished,
		"parameters_hash":  strings.TrimSpace(*parametersHash),
		"environment_hash": strings.TrimSpace(*environmentHash),
		"outputs":          outputs,
	}
	body, err := postEvydence(ctx, client, *apiURL, *apiKey, "/v1/builds", "github-actions-build-"+runID+"-"+runAttempt, payload)
	if err != nil {
		return err
	}
	buildID, err := responseDataID(body)
	if err != nil {
		return err
	}
	fmt.Println("build uploaded: " + buildID)
	if strings.TrimSpace(*attestationPath) == "" {
		return nil
	}
	cleaned, err := cleanOperatorPath(*attestationPath)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified attestation file.
	attestation, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	body, err = postRawEvydence(ctx, client, *apiURL, *apiKey, "/v1/builds/"+buildID+"/attestations", "github-actions-attestation-"+buildID, attestation)
	if err != nil {
		return err
	}
	attestationID, err := responseDataID(body)
	if err != nil {
		return err
	}
	fmt.Println("attestation uploaded: " + attestationID)
	return nil
}

func postEvydence(ctx context.Context, client *http.Client, apiURL, apiKey, path, idem string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return postRawEvydence(ctx, client, apiURL, apiKey, path, idem, body)
}

func postRawEvydence(ctx context.Context, client *http.Client, apiURL, apiKey, path, idem string, body []byte) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Idempotency-Key", idem)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, safeAPIError(resp.StatusCode, responseBody)
	}
	return responseBody, nil
}

func safeAPIError(status int, body []byte) error {
	var problem struct {
		Detail string `json:"detail"`
		Code   string `json:"code"`
		Ext    struct {
			Code string `json:"code"`
		} `json:"-"`
	}
	_ = json.Unmarshal(body, &problem)
	code := problem.Code
	if code == "" {
		code = problem.Ext.Code
	}
	detail := strings.TrimSpace(problem.Detail)
	if detail == "" {
		detail = http.StatusText(status)
	}
	if code != "" {
		return fmt.Errorf("evydence API request failed: status=%d code=%s detail=%s", status, code, detail)
	}
	return fmt.Errorf("evydence API request failed: status=%d detail=%s", status, detail)
}

func responseDataID(body []byte) (string, error) {
	var decoded struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if decoded.Data.ID == "" {
		return "", errors.New("evydence API response missing data.id")
	}
	return decoded.Data.ID, nil
}

func envRequired(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func atoiDefault(value string, fallback int) int {
	var out int
	if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &out); err != nil || out <= 0 {
		return fallback
	}
	return out
}
