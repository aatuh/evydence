package configartifact

import (
	"bytes"
	"strings"
	"testing"
)

func TestMergePreservesEveryByteOutsideTheOwnedSection(t *testing.T) {
	for _, path := range ownedPaths {
		t.Run(path, func(t *testing.T) {
			start, end := "<!-- BEGIN EVYDENCE GENERATED CONFIGURATION -->", "<!-- END EVYDENCE GENERATED CONFIGURATION -->"
			if path == ProductionEnvironmentPath {
				start, end = "# BEGIN EVYDENCE GENERATED CONFIGURATION", "# END EVYDENCE GENERATED CONFIGURATION"
			}
			for _, newline := range []string{"\n", "\r\n"} {
				prefix := "Operator explanation: PRIVATE_OPERATOR_CANARY  keep spacing." + newline
				suffix := newline + "Local operator instructions; keep this text exactly." + newline
				original := []byte(prefix + start + newline + "old generated settings" + newline + end + suffix)
				before := bytes.Clone(original)
				generated := []byte("new generated settings\nENV=production\n")
				merged, err := Merge(path, original, generated)
				if err != nil {
					t.Fatal(err)
				}
				want := []byte(prefix + start + newline + string(generated) + end + suffix)
				if !bytes.Equal(merged, want) || !bytes.Equal(original, before) {
					t.Fatal("merge changed operator bytes or its caller-owned input")
				}
				again, err := Merge(path, merged, generated)
				if err != nil || !bytes.Equal(merged, again) {
					t.Fatal("generation is not idempotent")
				}
				merged[0] = '!'
				if !bytes.Equal(original, before) {
					t.Fatal("merged output aliases the original operator document")
				}
			}
		})
	}
}

func TestMergeRejectsAmbiguousOrUnownedDocumentsWithoutExposingContent(t *testing.T) {
	const start = "<!-- BEGIN EVYDENCE GENERATED CONFIGURATION -->"
	const end = "<!-- END EVYDENCE GENERATED CONFIGURATION -->"
	valid := start + "\nold\n" + end + "\n"
	for _, tc := range []struct{ name, path, original, generated string }{
		{"unknown-path", "PRIVATE_OPERATOR_CANARY", valid, "fresh\n"},
		{"absolute-path", "/PRIVATE_OPERATOR_CANARY", valid, "fresh\n"},
		{"traversal", "docs/../PRIVATE_OPERATOR_CANARY", valid, "fresh\n"},
		{"missing", ConfigurationReferencePath, "PRIVATE_OPERATOR_CANARY", "fresh\n"},
		{"start-only", ConfigurationReferencePath, start + "\nPRIVATE_OPERATOR_CANARY\n", "fresh\n"},
		{"end-only", ConfigurationReferencePath, end + "\nPRIVATE_OPERATOR_CANARY\n", "fresh\n"},
		{"duplicate", ConfigurationReferencePath, valid + valid, "fresh\n"},
		{"reversed", ConfigurationReferencePath, end + "\nPRIVATE_OPERATOR_CANARY\n" + start, "fresh\n"},
		{"inline-start", ConfigurationReferencePath, "PRIVATE_OPERATOR_CANARY " + valid, "fresh\n"},
		{"inline-end", ConfigurationReferencePath, start + "\nPRIVATE_OPERATOR_CANARY " + end, "fresh\n"},
		{"trailing-marker-text", ConfigurationReferencePath, start + " PRIVATE_OPERATOR_CANARY\nold\n" + end, "fresh\n"},
		{"trailing-end-text", ConfigurationReferencePath, start + "\nold\n" + end + " PRIVATE_OPERATOR_CANARY", "fresh\n"},
		{"empty-generated", ConfigurationReferencePath, valid, ""},
		{"nested-generated-marker", ConfigurationReferencePath, valid, "PRIVATE_OPERATOR_CANARY\n" + end + "\n"},
		{"invalid-utf8", ConfigurationReferencePath, valid, "PRIVATE_OPERATOR_CANARY\xff"},
		{"invalid-original-utf8", ConfigurationReferencePath, "PRIVATE_OPERATOR_CANARY\xff\n" + valid, "fresh\n"},
		{"binary-generated", ConfigurationReferencePath, valid, "PRIVATE_OPERATOR_CANARY\x00"},
		{"binary-original", ConfigurationReferencePath, "PRIVATE_OPERATOR_CANARY\x00\n" + valid, "fresh\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := Merge(tc.path, []byte(tc.original), []byte(tc.generated))
			if err == nil || len(merged) != 0 || strings.Contains(err.Error(), "PRIVATE_OPERATOR_CANARY") {
				t.Fatal("invalid artifact escaped validation or exposed operator content")
			}
		})
	}
}

func TestMergeBoundsInputAndResultSizes(t *testing.T) {
	const limit = 4 << 20
	valid := []byte("<!-- BEGIN EVYDENCE GENERATED CONFIGURATION -->\nold\n<!-- END EVYDENCE GENERATED CONFIGURATION -->\n")
	large := bytes.Repeat([]byte{'x'}, limit+1)
	prefix := bytes.Repeat([]byte{'x'}, limit-len(valid)-8)
	prefix[len(prefix)-1] = '\n'
	for _, tc := range []struct{ original, generated []byte }{
		{large, []byte("fresh\n")},
		{valid, large},
		{append(prefix, valid...), bytes.Repeat([]byte{'x'}, 32)},
	} {
		merged, err := Merge(ConfigurationReferencePath, tc.original, tc.generated)
		if err == nil || len(merged) != 0 {
			t.Fatal("artifact size bound was not enforced before returning output")
		}
	}
}

func TestMergeSeparatesAnUnterminatedGeneratedLineFromItsEndMarker(t *testing.T) {
	original := []byte("# BEGIN EVYDENCE GENERATED CONFIGURATION\nold\n# END EVYDENCE GENERATED CONFIGURATION")
	merged, err := Merge(ProductionEnvironmentPath, original, []byte("ENV=production"))
	if err != nil || !bytes.Contains(merged, []byte("ENV=production\n# END")) {
		t.Fatal("generated content consumed its closing ownership marker")
	}
}
