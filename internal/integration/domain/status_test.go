package domain

import "testing"

func TestCollectorStatusValidation(t *testing.T) {
	for _, value := range []string{CollectorStatusActiveValue, CollectorStatusDisabledValue, CollectorStatusRevokedValue} {
		status, err := ParseCollectorStatus(" " + value + " ")
		if err != nil || status.String() != value || status.IsZero() {
			t.Fatalf("ParseCollectorStatus(%q)=(%q, %v)", value, status.String(), err)
		}
	}
	if _, err := ParseCollectorStatus("unknown"); err == nil {
		t.Fatal("unknown collector status was accepted")
	}
	if !(CollectorStatus{}).IsZero() {
		t.Fatal("zero collector status was not reported")
	}
}
