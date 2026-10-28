package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// The expected results were recorded from the official Go v0.315.1 parser
// with default options before removing its server-sized QA module graph.
// Include every stable function and explicit syntax/type/feature controls.
func TestQueryParserRecordedGoOracle(t *testing.T) {
	data, err := os.ReadFile("testdata/promql-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Query string `json:"query"`
		Valid bool   `json:"valid"`
	}
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) < 114 {
		t.Fatal("missing recorded parser controls", err)
	}
	root := repositoryRoot(t)
	for _, tc := range cases {
		t.Run(tc.Query, func(t *testing.T) {
			facts, err := parseQueryFacts(t.Context(), root, tc.Query)
			if err != nil && !errors.Is(err, errQuerySyntax) {
				t.Fatal(err)
			}
			if err == nil {
				err = validateQuerySyntax(facts)
			}
			if (err == nil) != tc.Valid {
				t.Fatalf("recorded validity=%v: %v", tc.Valid, err)
			}
		})
	}
}

func TestParserProtocolRejectsMalformedOrUnexpectedOutput(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"schema":"unknown","valid":true}`,
		`{"schema":"evydence-promql-facts.v1","valid":true,"unexpected":"SYNTHETIC_SECRET"}`,
		`{"schema":"evydence-promql-facts.v1","valid":true} {}`,
		strings.Repeat(" ", (1<<20)+1),
	} {
		if _, err := decodeQueryFacts([]byte(raw)); err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("malformed parser protocol accepted or private output leaked", err)
		}
	}
}

func TestParserEnvironmentExcludesSecretsAndNodePreloads(t *testing.T) {
	for _, key := range []string{"GH_TOKEN", "EVYDENCE_DATABASE_URL", "NODE_OPTIONS", "NODE_PATH", "HTTP_PROXY"} {
		t.Setenv(key, "SYNTHETIC_SECRET")
	}
	for _, entry := range parserEnvironment() {
		if strings.Contains(entry, "SYNTHETIC_SECRET") {
			t.Fatal("parser inherited a secret or ambient Node/network configuration")
		}
	}
}

func TestQueryParserCancellationPrecedesProcessStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := parseQueryFacts(ctx, t.TempDir(), "up"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled parsing did not preserve cancellation", err)
	}
}

func TestQueryParserCancelsRunningProcess(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "site", "marketing")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "tools", "cmd", "observability-check", "query_parser.cjs")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	path := filepath.Join(bin, "node")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := parseQueryFacts(ctx, root, "up")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatal("running parser did not stop within its context deadline", err)
	}
}
