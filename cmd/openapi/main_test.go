package main

import (
	"bytes"
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
