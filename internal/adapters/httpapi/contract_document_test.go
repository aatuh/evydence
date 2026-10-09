package httpapi

import (
	"bytes"
	"testing"
)

func TestGenerateOpenAPIUsesSharedContractsWithoutRuntimeComposition(t *testing.T) {
	first, err := GenerateOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateOpenAPI()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("contract generation is not deterministic: %v", err)
	}
	native, err := NewNativeServerWithOptionsContext(t.Context(), nativeConstructorOptions())
	if err != nil {
		t.Fatal(err)
	}
	document, err := native.OpenAPI()
	if err != nil || !bytes.Equal(first, document) {
		t.Fatalf("contract-only generation diverged from native routes: %v", err)
	}
	// The documentation path cannot relax mandatory runnable-server ports.
	if _, err := NewNativeServerWithOptionsContext(t.Context(), ServerOptions{}); err == nil {
		t.Fatal("contract generation enabled incomplete native runtime construction")
	}
}
