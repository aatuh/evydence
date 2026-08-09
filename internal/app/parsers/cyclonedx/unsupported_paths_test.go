package cyclonedx

import (
	"slices"
	"strings"
	"testing"
)

func TestParseBoundedReportsEveryPreservedStandardConstructItDoesNotNormalize(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":1,"properties":[{"name":"root","value":"kept"}],"components":[{"type":"library","name":"parent","group":"example.org","cpe":"cpe:2.3:a:example:parent:1.0:*:*:*:*:*:*:*","scope":"required","components":[{"type":"library","name":"child"}],"tags":["runtime"]}],"dependencies":[{"ref":"parent","provides":["child"]}]}`)
	got, err := ParseBounded(raw, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"serialNumber", "version", "properties", "components[].group", "components[].cpe", "components[].scope", "components[].components", "components[].tags", "dependencies[].provides"} {
		if !slices.Contains(got.UnsupportedPaths, want) {
			t.Fatalf("paths=%#v missing %q", got.UnsupportedPaths, want)
		}
	}
	if len(got.Warnings) != len(got.UnsupportedPaths) {
		t.Fatalf("warnings=%d paths=%d", len(got.Warnings), len(got.UnsupportedPaths))
	}
}

func TestParserVersionTracksNormalizationSemanticChange(t *testing.T) {
	if ParserVersion != "cyclonedx-json.v1.3.1" {
		t.Fatalf("ParserVersion=%q", ParserVersion)
	}
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}`)
	got, err := ParseBounded(raw, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], ParserVersion) {
		t.Fatalf("warnings=%#v", got.Warnings)
	}
}
