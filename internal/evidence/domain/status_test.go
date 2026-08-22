package domain

import "testing"

func TestEvidenceLifecycleAndSubjectReferenceValidation(t *testing.T) {
	for _, value := range []string{
		EvidenceLifecycleAcceptedValue,
		EvidenceLifecycleAmendmentValue,
		EvidenceLifecycleRedactionValue,
		EvidenceLifecycleTombstoneValue,
		EvidenceLifecycleRetentionMarkerValue,
	} {
		state, err := ParseEvidenceLifecycleState(" " + value + " ")
		if err != nil || state.String() != value || state.IsZero() {
			t.Fatalf("ParseEvidenceLifecycleState(%q)=(%q, %v)", value, state.String(), err)
		}
	}
	if _, err := ParseEvidenceLifecycleState("unknown"); err == nil {
		t.Fatal("unknown lifecycle state was accepted")
	}
	if !(EvidenceLifecycleState{}).IsZero() {
		t.Fatal("zero lifecycle state was not reported")
	}
	reference, err := NewSubjectReference(" artifact ", " art_1 ", " sha256:abc ")
	if err != nil || reference.Type != "artifact" || reference.ID != "art_1" || reference.Digest != "sha256:abc" {
		t.Fatalf("NewSubjectReference()=(%#v, %v)", reference, err)
	}
	if _, err := NewSubjectReference("", "art_1", ""); err == nil {
		t.Fatal("empty subject type was accepted")
	}
	if _, err := NewSubjectReference("artifact", "", ""); err == nil {
		t.Fatal("empty subject ID was accepted")
	}
}
