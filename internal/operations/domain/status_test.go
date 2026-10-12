package domain

import "testing"

func TestIncidentStatusValidation(t *testing.T) {
	for _, value := range []string{IncidentStatusOpenValue, IncidentStatusContainedValue, IncidentStatusResolvedValue, IncidentStatusClosedValue} {
		status, err := ParseIncidentStatus(" " + value + " ")
		if err != nil || status.String() != value || status.IsZero() {
			t.Fatalf("ParseIncidentStatus(%q)=(%q, %v)", value, status.String(), err)
		}
	}
	if _, err := ParseIncidentStatus("unknown"); err == nil {
		t.Fatal("unknown incident status was accepted")
	}
	if !(IncidentStatus{}).IsZero() {
		t.Fatal("zero incident status was not reported")
	}
}
