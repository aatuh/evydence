package dsse

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"testing"
)

func TestConfiguredDSSEPoliciesNeverCombineRootAndBuilderTrust(t *testing.T) {
	payload, err := os.ReadFile("../../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := signedEnvelope(t, payload, private)
	policy := Policy{Roots: []TrustRoot{{ID: "root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(public)}}, AllowedPredicateTypes: []string{testPredicate}, ExpectedBuilderIDs: []string{testBuilder}, RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}, ExpectedSubjectDigests: []string{testSubject}}
	wrongKey := policy
	wrongKey.Roots = []TrustRoot{{ID: "other", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(other)}}
	wrongBuilder := policy
	wrongBuilder.ExpectedBuilderIDs = []string{"other-builder"}
	got, err := VerifyConfiguredPolicies(t.Context(), raw, []Policy{wrongKey, wrongBuilder})
	if err != nil || got.Passed() || got.Check("dsse_pae_signature") != CheckPassed || got.Check("builder_identity") != CheckFailed {
		t.Fatal("policies combined", got, err)
	}
	got, err = VerifyConfiguredPolicies(t.Context(), raw, []Policy{wrongKey, wrongBuilder, policy})
	if err != nil || !got.Passed() || len(got.AcceptedRootIDs) != 1 || got.AcceptedRootIDs[0] != "root" {
		t.Fatal(got, err)
	}
	got, err = VerifyConfiguredPolicies(t.Context(), raw, nil)
	if err != nil || len(got.Checks) != 7 || got.Passed() {
		t.Fatal(got, err)
	}
	for _, check := range got.Checks {
		if check.Result != CheckNotVerified {
			t.Fatal("missing policy assigned trust", check)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := VerifyConfiguredPolicies(ctx, raw, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled inspection continued", err)
	}
}
