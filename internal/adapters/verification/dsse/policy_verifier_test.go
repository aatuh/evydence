package dsse

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestPolicyVerifierPreservesChecksAndIsolatesCompleteRootPolicies(t *testing.T) {
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
	root := verificationdomain.DSSETrustRoot{ID: "root", TenantID: "tenant", Name: "Root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(public), Status: "active", SchemaVersion: verificationdomain.DSSETrustRootSchemaVersion, CreatedAt: time.Unix(10, 0), AllowedPredicateTypes: []string{testPredicate}, ExpectedBuilderIDs: []string{testBuilder}, RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}}
	wrongKey := root
	wrongKey.ID, wrongKey.PublicKey = "wrong-key", base64.StdEncoding.EncodeToString(other)
	wrongBuilder := root
	wrongBuilder.ID, wrongBuilder.ExpectedBuilderIDs = "wrong-builder", []string{"other-builder"}
	for _, roots := range [][]verificationdomain.DSSETrustRoot{nil, {wrongKey, wrongBuilder}, {wrongKey, wrongBuilder, root}} {
		input := verificationapp.DSSEPolicyVerification{TenantID: "tenant", Envelope: raw, Roots: roots, ExpectedSubjectDigests: []string{testSubject}}
		got, err := (PolicyVerifier{}).VerifyDSSEPolicies(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		policies := make([]Policy, 0, len(roots))
		for _, root := range roots {
			policies = append(policies, Policy{Roots: []TrustRoot{{ID: root.ID, KeyID: root.KeyID, Algorithm: root.Algorithm, PublicKey: root.PublicKey}}, AllowedPredicateTypes: root.AllowedPredicateTypes, ExpectedBuilderIDs: root.ExpectedBuilderIDs, RequiredClaims: root.RequiredClaims, ExpectedSubjectDigests: []string{testSubject}})
		}
		original, err := VerifyConfiguredPolicies(t.Context(), raw, policies)
		if err != nil {
			t.Fatal(err)
		}
		want := verificationapp.DSSEVerificationFacts{AcceptedRootIDs: append([]string(nil), original.AcceptedRootIDs...)}
		for _, check := range original.Checks {
			want.Checks = append(want.Checks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("policy receipt changed: got=%#v want=%#v", got, want)
		}
		allPassed := len(got.Checks) > 0
		for _, check := range got.Checks {
			if check.Result != CheckPassed {
				allPassed = false
			}
		}
		if len(roots) < 3 && allPassed {
			t.Fatal("missing/combined policies assigned full trust", got)
		}
		if len(roots) == 0 && len(got.AcceptedRootIDs) != 0 {
			t.Fatal("missing root assigned key trust", got)
		}
		if len(roots) == 3 && (!allPassed || len(got.AcceptedRootIDs) != 1 || got.AcceptedRootIDs[0] != root.ID) {
			t.Fatal("complete policy did not verify", got)
		}
	}
}

func TestPolicyVerifierRejectsForeignPoliciesCancellationAndUnsafeErrors(t *testing.T) {
	input := verificationapp.DSSEPolicyVerification{TenantID: "tenant", Envelope: []byte("PRIVATE_PAYLOAD_CANARY invalid envelope"), Roots: []verificationdomain.DSSETrustRoot{{TenantID: "other"}}}
	if facts, err := (PolicyVerifier{}).VerifyDSSEPolicies(t.Context(), input); !errors.Is(err, verificationapp.ErrConflict) || len(facts.Checks) != 0 || strings.Contains(err.Error(), "PRIVATE_PAYLOAD_CANARY") {
		t.Fatal("foreign policy assigned trust or leaked payload", facts, err)
	}
	input.Roots = nil
	if facts, err := (PolicyVerifier{}).VerifyDSSEPolicies(t.Context(), input); !errors.Is(err, verificationapp.ErrValidation) || len(facts.Checks) != 0 || strings.Contains(err.Error(), "PRIVATE_PAYLOAD_CANARY") {
		t.Fatal("parser error leaked payload", facts, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (PolicyVerifier{}).VerifyDSSEPolicies(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := (PolicyVerifier{}).VerifyDSSEPolicies(nil, input); !errors.Is(err, verificationapp.ErrValidation) { //nolint:staticcheck // Defensive nil-context rejection.
		t.Fatal("nil context accepted", err)
	}
}
