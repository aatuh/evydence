package domain

import (
	"encoding/json"
	"strings"
	"testing"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestCosignReceiptCompatibilityCopiesPolicyAndPreservesWireFields(t *testing.T) {
	owned := verificationdomain.CosignVerification{ID: "receipt", VerifierLibraryVersion: "library", TrustRootVersion: "root", VerificationMode: "key", Checks: []verificationdomain.VerifyCheck{{Name: "signature", Result: "passed"}}, Profile: verificationdomain.VerificationProfile{RequiredChecks: []string{"signature"}, TrustMaterial: []string{"public trust reference"}, Limitations: []string{"offline only"}}, Limitations: []string{"bounded"}}
	legacy := CosignVerificationFromContextModel(owned)
	legacy.Checks[0].Name = "changed"
	legacy.Profile.RequiredChecks[0] = "changed"
	legacy.Profile.TrustMaterial[0] = "changed"
	legacy.Profile.Limitations[0] = "changed"
	legacy.Limitations[0] = "changed"
	if owned.Checks[0].Name != "signature" || owned.Profile.RequiredChecks[0] != "signature" || owned.Profile.TrustMaterial[0] != "public trust reference" || owned.Profile.Limitations[0] != "offline only" || owned.Limitations[0] != "bounded" {
		t.Fatal("receipt mapper aliases mutable policy", owned)
	}
	raw, err := json.Marshal(CosignVerificationFromContextModel(owned))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"verifier_library_version":"library"`, `"trust_root_version":"root"`, `"verification_mode":"key"`} {
		if !strings.Contains(string(raw), field) {
			t.Fatal("wire receipt identity changed", string(raw))
		}
	}
}
