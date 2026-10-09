package domain

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestDSSETrustRootCompatibilityPreservesEveryFieldAndOwnsPolicyLists(t *testing.T) {
	root := DSSETrustRoot{ID: "root", TenantID: "tenant", Name: "Builder", KeyID: "key", Algorithm: "Ed25519", PublicKey: "public", AllowedPredicateTypes: []string{"predicate"}, ExpectedBuilderIDs: []string{"builder"}, RequiredClaims: []string{"claim"}, Status: "active", SchemaVersion: "root.v1", CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	owned := DSSETrustRootToContextModel(root)
	copy := DSSETrustRootFromContextModel(owned)
	if !reflect.DeepEqual(copy, root) {
		t.Fatal("trust-root fields changed", copy)
	}
	first, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(copy)
	if err != nil || string(first) != string(second) {
		t.Fatal("wire shape changed", err)
	}
	owned.AllowedPredicateTypes[0] = "changed"
	owned.ExpectedBuilderIDs[0] = "changed"
	owned.RequiredClaims[0] = "changed"
	if root.AllowedPredicateTypes[0] == "changed" || root.ExpectedBuilderIDs[0] == "changed" || root.RequiredClaims[0] == "changed" || copy.AllowedPredicateTypes[0] == "changed" || copy.ExpectedBuilderIDs[0] == "changed" || copy.RequiredClaims[0] == "changed" {
		t.Fatal("mutable policy alias")
	}
}
