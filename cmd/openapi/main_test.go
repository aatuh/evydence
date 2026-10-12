package main

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestRunWritesOpenAPI(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), `"openapi"`) || !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("unexpected OpenAPI output: %.80q", out.String())
	}
}

func TestOpenAPICommandDoesNotImportLegacyApplication(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if path == "github.com/aatuh/evydence/internal/app" {
			t.Fatal("OpenAPI generation still depends on the legacy application aggregate")
		}
	}
}

type unavailableOutput struct{}

func (unavailableOutput) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestRunPropagatesOutputError(t *testing.T) {
	if err := run(unavailableOutput{}); err == nil || err.Error() != "output unavailable" {
		t.Fatalf("output failure lost: %v", err)
	}
}
