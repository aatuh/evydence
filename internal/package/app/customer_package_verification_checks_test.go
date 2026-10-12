package app

import (
	"reflect"
	"testing"
)

func TestCustomerPackageVerificationCheckSummariesPreservesPublicShapeAndOwnership(t *testing.T) {
	values := []CustomerPackageVerificationCheck{{Name: "z", Result: "limited", Detail: "recorded scope"}, {Name: "a", Result: "failed"}, {Name: "a", Result: "error", Detail: "provider unavailable"}}
	want := []map[string]any{{"name": "a", "result": "failed", "detail": ""}, {"name": "a", "result": "error", "detail": "provider unavailable"}, {"name": "z", "result": "limited", "detail": "recorded scope"}}
	got := CustomerPackageVerificationCheckSummaries(values)
	if !reflect.DeepEqual(got, want) || values[0].Name != "z" {
		t.Fatalf("public check shape/order or input mutated: got=%#v input=%#v", got, values)
	}
	got[0]["result"] = "passed"
	if values[1].Result != "failed" || !reflect.DeepEqual(CustomerPackageVerificationCheckSummaries(values), want) {
		t.Fatal("check metadata aliases caller or another result")
	}
	if empty := CustomerPackageVerificationCheckSummaries(nil); empty == nil || len(empty) != 0 {
		t.Fatal("legacy empty checks must be a nonnil collection")
	}
}
