package domain

import "testing"

func TestDecisionStatusValidation(t *testing.T) {
	for _, value := range []string{
		DecisionStatusAffectedValue,
		DecisionStatusNotAffectedValue,
		DecisionStatusFixedValue,
		DecisionStatusUnderInvestigationValue,
	} {
		state, err := ParseDecisionStatus(" " + value + " ")
		if err != nil || state.String() != value || state.IsZero() {
			t.Fatalf("ParseDecisionStatus(%q)=(%q, %v)", value, state.String(), err)
		}
		if !state.CanTransitionTo(state) {
			t.Fatalf("valid state %q could not transition", value)
		}
	}
	if _, err := ParseDecisionStatus("unknown"); err == nil {
		t.Fatal("unknown decision status was accepted")
	}
	if !(DecisionStatus{}).IsZero() || (DecisionStatus{}).CanTransitionTo(DecisionStatus{}) {
		t.Fatal("zero decision state was treated as valid")
	}
}
