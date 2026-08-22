package cyclonedx

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSchemaValidatorRejectsOversizedSchemaResources(t *testing.T) {
	oversized := func(schema string) io.Reader {
		return io.MultiReader(
			strings.NewReader(schema),
			strings.NewReader(strings.Repeat(" ", int(maxSchemaResourceBytes))),
		)
	}
	tests := []struct {
		name string
		bom  io.Reader
		spdx io.Reader
		jsf  io.Reader
	}{
		{
			name: "bom",
			bom:  oversized(testBOMSchema),
			spdx: strings.NewReader(testSPDXSchema),
			jsf:  strings.NewReader(testJSFSchema),
		},
		{
			name: "spdx",
			bom:  strings.NewReader(testBOMSchema),
			spdx: oversized(testSPDXSchema),
			jsf:  strings.NewReader(testJSFSchema),
		},
		{
			name: "jsf",
			bom:  strings.NewReader(testBOMSchema),
			spdx: strings.NewReader(testSPDXSchema),
			jsf:  oversized(testJSFSchema),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSchemaValidator(test.bom, test.spdx, test.jsf); !errors.Is(err, ErrInvalid) {
				t.Fatalf("oversized schema err=%v, want invalid", err)
			}
		})
	}
}
