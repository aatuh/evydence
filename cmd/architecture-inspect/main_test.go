package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEmitsSourceInventoryWithoutRunningTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cmd/example"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cmd/example/main.go"), []byte("package main\nfunc init(){panic(\"never execute\")}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	if err := run(context.Background(), []string{"-root", root, "-module", "example.com/project"}, &out, &diagnostic); err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Version int `json:"version"`
		Files   []struct {
			Path    string `json:"path"`
			Package string `json:"package"`
		} `json:"files"`
	}
	if err := json.Unmarshal(out.Bytes(), &inventory); err != nil || inventory.Version != 1 || len(inventory.Files) != 1 || inventory.Files[0].Path != "cmd/example/main.go" || inventory.Files[0].Package != "example.com/project/cmd/example" || diagnostic.Len() != 0 {
		t.Fatalf("invalid inventory: %s diagnostic=%s err=%v", &out, &diagnostic, err)
	}
}

func TestRunRejectsArgumentsAndCancellationWithoutPartialOutput(t *testing.T) {
	for _, args := range [][]string{{"-unknown"}, {"-root"}, {"positional"}, {"-module", "../escape"}, {"-root", "missing"}} {
		var out, diagnostic bytes.Buffer
		if err := run(context.Background(), args, &out, &diagnostic); err == nil || out.Len() != 0 {
			t.Fatalf("invalid arguments accepted: %q output=%s err=%v", args, &out, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostic bytes.Buffer
	if err := run(ctx, nil, &out, &diagnostic); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatalf("cancellation lost: %s err=%v", &out, err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunPropagatesOutputFailures(t *testing.T) {
	root := t.TempDir()
	if err := run(context.Background(), []string{"-root", root}, failingWriter{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("output error lost: %v", err)
	}
}
