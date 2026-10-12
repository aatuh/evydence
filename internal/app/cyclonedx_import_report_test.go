package app

import (
	"reflect"
	"testing"
)

func TestCycloneDXEvidenceMetadataIncludesExplicitImportReport(t *testing.T) {
	normalized := cyclonedxNormalization{
		SpecVersion:      "1.6",
		ParserVersion:    ParserVersionCycloneDXJSON,
		Warnings:         []string{"services is preserved in raw evidence but is not normalized"},
		UnsupportedPaths: []string{"services"},
	}
	metadata := normalized.evidenceMetadata()
	report, ok := metadata["import_report"].(map[string]any)
	if !ok {
		t.Fatalf("import_report=%#v", metadata["import_report"])
	}
	if got, _ := report["parser_version"].(string); got != ParserVersionCycloneDXJSON {
		t.Fatalf("parser_version=%q", got)
	}
	if got, _ := report["warnings"].([]string); !reflect.DeepEqual(got, normalized.Warnings) {
		t.Fatalf("warnings=%#v want=%#v", got, normalized.Warnings)
	}
	if got, _ := report["unsupported_constructs"].([]string); !reflect.DeepEqual(got, normalized.UnsupportedPaths) {
		t.Fatalf("unsupported_constructs=%#v want=%#v", got, normalized.UnsupportedPaths)
	}

	// Reporting slices must not alias the normalization state or the legacy
	// compatibility keys, so downstream enrichment cannot rewrite the record.
	report["warnings"].([]string)[0] = "changed"
	if normalized.Warnings[0] == "changed" || metadata["normalization_warnings"].([]string)[0] == "changed" {
		t.Fatal("import report warnings alias another metadata view")
	}
}
