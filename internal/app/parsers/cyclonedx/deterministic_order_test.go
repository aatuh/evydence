package cyclonedx

import (
	"reflect"
	"testing"
)

func TestParseBoundedNormalizesComponentsDeterministicallyAcrossSourceOrder(t *testing.T) {
	first := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"zeta","version":"1.0.0","bom-ref":"zeta-ref"},{"type":"library","name":"alpha","version":"2.0.0","purl":"pkg:golang/example.org/alpha@v2.0.0"}]}`)
	second := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"alpha","version":"2.0.0","purl":"pkg:golang/example.org/alpha@v2.0.0"},{"type":"library","name":"zeta","version":"1.0.0","bom-ref":"zeta-ref"}]}`)

	gotFirst, err := ParseBounded(first, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := ParseBounded(second, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotFirst.Components, gotSecond.Components) {
		t.Fatalf("component normalization depends on source order:\nfirst=%#v\nsecond=%#v", gotFirst.Components, gotSecond.Components)
	}
	if len(gotFirst.Components) != 2 || gotFirst.Components[0].Identity > gotFirst.Components[1].Identity {
		t.Fatalf("components are not identity-sorted: %#v", gotFirst.Components)
	}
}
