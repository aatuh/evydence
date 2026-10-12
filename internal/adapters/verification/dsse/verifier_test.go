package dsse

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	testPayloadType = "application/vnd.in-toto+json"
	testPredicate   = "https://slsa.dev/provenance/v1"
	testBuilder     = "https://github.com/actions/runner"
	testSubject     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestVerifyAttestationEnforcesPAEAndTrustedPolicy(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "intoto", "slsa-provenance-v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	envelope := signedEnvelope(t, payload, privateKey)
	policy := Policy{
		Roots:                  []TrustRoot{{ID: "dtr-1", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}},
		AllowedPredicateTypes:  []string{testPredicate},
		ExpectedBuilderIDs:     []string{testBuilder},
		RequiredClaims:         []string{"builder_id", "build_type", "external_parameters"},
		ExpectedSubjectDigests: []string{testSubject},
	}
	result, err := Verify(context.Background(), envelope, policy)
	if err != nil {
		t.Fatalf("verify valid envelope: %v", err)
	}
	if !result.Passed() {
		t.Fatalf("valid receipt did not pass: %#v", result)
	}

	wrongPAE := signedEnvelopeWithMessage(t, payload, privateKey, payload)
	result, err = Verify(context.Background(), wrongPAE, policy)
	if err != nil {
		t.Fatalf("verify PAE-tampered envelope: %v", err)
	}
	if result.Check("dsse_pae_signature") != CheckFailed {
		t.Fatalf("PAE check = %q, want failed: %#v", result.Check("dsse_pae_signature"), result)
	}

	tamperedPayload := append(append([]byte(nil), payload...), '\n')
	result, err = Verify(context.Background(), signedEnvelopeWithMessage(t, tamperedPayload, privateKey, securedsse.PAE(testPayloadType, payload)), policy)
	if err != nil {
		t.Fatalf("verify payload-tampered envelope: %v", err)
	}
	if result.Check("dsse_pae_signature") != CheckFailed {
		t.Fatalf("tampered payload passed signature check: %#v", result)
	}

	tamperedSubject := bytes.Replace(payload, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 1)
	result, err = Verify(context.Background(), signedEnvelope(t, tamperedSubject, privateKey), policy)
	if err != nil {
		t.Fatalf("verify subject-tampered envelope: %v", err)
	}
	if result.Check("subject_digest") != CheckFailed {
		t.Fatalf("tampered subject passed: %#v", result)
	}

	tamperedPredicate := bytes.Replace(payload, []byte(testPredicate), []byte("https://example.invalid/provenance/v1"), 1)
	result, err = Verify(context.Background(), signedEnvelope(t, tamperedPredicate, privateKey), policy)
	if err != nil {
		t.Fatalf("verify predicate-tampered envelope: %v", err)
	}
	if result.Check("predicate_type") != CheckNotVerified {
		t.Fatalf("tampered predicate result: %#v", result)
	}

	result, err = Verify(context.Background(), signedEnvelopeForType(t, payload, "application/example+json", privateKey, securedsse.PAE(testPayloadType, payload)), policy)
	if err != nil {
		t.Fatalf("verify envelope-tampered envelope: %v", err)
	}
	if result.Check("dsse_pae_signature") != CheckFailed {
		t.Fatalf("tampered envelope passed signature check: %#v", result)
	}

	policy.ExpectedBuilderIDs = []string{"https://example.invalid/other-builder"}
	result, err = Verify(context.Background(), envelope, policy)
	if err != nil {
		t.Fatalf("verify wrong-builder envelope: %v", err)
	}
	if result.Check("builder_identity") != CheckFailed || result.Passed() {
		t.Fatalf("wrong builder passed: %#v", result)
	}
}

func TestVerifyAttestationReportsUnsupportedPredicateAsNotVerified(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "intoto", "slsa-provenance-v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	policy := Policy{
		Roots:                  []TrustRoot{{ID: "dtr-1", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}},
		AllowedPredicateTypes:  []string{"https://example.invalid/predicate/v1"},
		ExpectedBuilderIDs:     []string{testBuilder},
		RequiredClaims:         []string{"builder_id"},
		ExpectedSubjectDigests: []string{testSubject},
	}
	result, err := Verify(context.Background(), signedEnvelope(t, payload, privateKey), policy)
	if err != nil {
		t.Fatalf("verify unsupported predicate: %v", err)
	}
	if result.Check("predicate_type") != CheckNotVerified || result.Passed() {
		t.Fatalf("unsupported predicate result: %#v", result)
	}
}

func TestVerifyAttestationRejectsUnlinkedSubjects(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "intoto", "slsa-provenance-v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	result, err := Verify(context.Background(), signedEnvelope(t, payload, privateKey), Policy{
		Roots:                 []TrustRoot{{ID: "dtr-1", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}},
		AllowedPredicateTypes: []string{testPredicate},
		ExpectedBuilderIDs:    []string{testBuilder},
		RequiredClaims:        []string{"builder_id", "build_type", "external_parameters"},
	})
	if err != nil {
		t.Fatalf("verify unlinked subject: %v", err)
	}
	if result.Check("subject_digest") != CheckFailed || result.Passed() {
		t.Fatalf("unlinked subject result: %#v", result)
	}
}

func TestParsePreservesStructurallyValidUnsupportedPayloadType(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "dsse", "unsupported-payload-type.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	result, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse unsupported payload fixture: %v", err)
	}
	if result.PayloadType != "application/example+json" || result.PredicateType != testPredicate {
		t.Fatalf("parsed fixture = %#v", result)
	}
}

func signedEnvelope(t *testing.T, payload []byte, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	return signedEnvelopeWithMessage(t, payload, privateKey, securedsse.PAE(testPayloadType, payload))
}

func signedEnvelopeWithMessage(t *testing.T, payload []byte, privateKey ed25519.PrivateKey, message []byte) []byte {
	t.Helper()
	return signedEnvelopeForType(t, payload, testPayloadType, privateKey, message)
}

func signedEnvelopeForType(t *testing.T, payload []byte, payloadType string, privateKey ed25519.PrivateKey, message []byte) []byte {
	t.Helper()
	return []byte(`{"payloadType":"` + payloadType + `","payload":"` + base64.StdEncoding.EncodeToString(payload) + `","signatures":[{"keyid":"root-1","sig":"` + base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message)) + `"}]}`)
}
