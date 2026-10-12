package cyclonedx

import (
	"reflect"
	"testing"
)

func TestParseBoundedCanonicalizesDuplicateDependencyRefs(t *testing.T) {
	first := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"same","dependsOn":["z"]},{"ref":"same","dependsOn":["a"]}]}`)
	second := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"same","dependsOn":["a"]},{"ref":"same","dependsOn":["z"]}]}`)

	gotFirst, err := ParseBounded(first, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := ParseBounded(second, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotFirst.Dependencies, gotSecond.Dependencies) {
		t.Fatalf("source order leaks into dependencies:\nfirst=%#v\nsecond=%#v", gotFirst.Dependencies, gotSecond.Dependencies)
	}
}
