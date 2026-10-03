package sigstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	officialFixtureDigest = "sha256:bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
	officialFixtureIssuer = "http://oidc.local:8080"
	officialFixtureSAN    = "foo!oidc.local"
)

func TestVerifyOfficialKeylessBundle(t *testing.T) {
	verifier := newOfficialFixtureVerifier(t)
	bundle := readFixture(t, "official-othername.bundle.json")

	receipt, err := verifier.VerifyCosign(context.Background(), Request{
		Bundle:           bundle,
		ArtifactDigest:   officialFixtureDigest,
		ExpectedIdentity: officialFixtureSAN,
		ExpectedIssuer:   officialFixtureIssuer,
		Mode:             VerificationModeKeyless,
		Offline:          true,
	})
	if err != nil {
		t.Fatalf("verify official bundle: %v", err)
	}
	if receipt.LibraryVersion != LibraryVersion || receipt.TrustRootVersion != "sigstore-go-scaffolding-1" {
		t.Fatalf("unsafe receipt versions: %#v", receipt)
	}
	if receipt.CertificateIdentity != officialFixtureSAN || receipt.CertificateIssuer != officialFixtureIssuer {
		t.Fatalf("verified identity receipt: %#v", receipt)
	}
	assertCheck(t, receipt.Checks, "cryptographic_signature", "passed")
	assertCheck(t, receipt.Checks, "subject_digest", "passed")
	assertCheck(t, receipt.Checks, "fulcio_trust_root", "passed")
	assertCheck(t, receipt.Checks, "certificate_validity", "passed")
	assertCheck(t, receipt.Checks, "certificate_identity_policy", "passed")
	assertCheck(t, receipt.Checks, "rekor_inclusion_proof", "passed")
}

func TestVerifyOfficialKeylessBundleFailsClosed(t *testing.T) {
	verifier := newOfficialFixtureVerifier(t)
	bundle := readFixture(t, "official-othername.bundle.json")
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "wrong digest", mutate: func(in *Request) {
			in.ArtifactDigest = "sha256:ac103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
		}},
		{name: "wrong identity", mutate: func(in *Request) { in.ExpectedIdentity = "other@oidc.local" }},
		{name: "wrong issuer", mutate: func(in *Request) { in.ExpectedIssuer = "https://issuer.example.invalid" }},
		{name: "bad signature", mutate: func(in *Request) { in.Bundle = tamperBundle(t, in.Bundle, "signature") }},
		{name: "bad Rekor proof", mutate: func(in *Request) { in.Bundle = tamperBundle(t, in.Bundle, "proof") }},
		{name: "online profile", mutate: func(in *Request) { in.Offline = false }},
		{name: "malformed bundle", mutate: func(in *Request) { in.Bundle = []byte(`{"mediaType":"not-a-bundle"}`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := Request{Bundle: bundle, ArtifactDigest: officialFixtureDigest, ExpectedIdentity: officialFixtureSAN, ExpectedIssuer: officialFixtureIssuer, Mode: VerificationModeKeyless, Offline: true}
			tc.mutate(&in)
			_, err := verifier.VerifyCosign(context.Background(), in)
			if !errors.Is(err, ErrVerificationFailed) && !errors.Is(err, ErrOnlineVerificationUnavailable) {
				t.Fatalf("err=%v, want safe verification failure", err)
			}
		})
	}
}

func TestNewAcceptsConfiguredKeyVerificationMaterial(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	verifier, err := New(Config{
		TrustedPublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		TrustRootVersion:    "operator-key.v1",
	})
	if err != nil {
		t.Fatalf("load configured public key: %v", err)
	}
	if verifier == nil || verifier.trustRootVersion != "operator-key.v1" {
		t.Fatalf("configured key verifier = %#v", verifier)
	}
}

func TestSigstoreLibraryRejectsCertificateExpiredAtObserverTime(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("new virtual Sigstore: %v", err)
	}
	artifact := []byte("certificate-expiry-regression")
	identity := "ci@example.test"
	issuer := "https://issuer.example.test"
	// The virtual Fulcio leaf is valid for only ten minutes. Its future Rekor
	// observer time must therefore make verification fail, rather than allowing
	// current-time certificate validity to mask the expired signing evidence.
	entity, err := virtualSigstore.SignAtTime(identity, issuer, artifact, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("sign expired virtual bundle: %v", err)
	}
	verifier, err := verify.NewVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	policyIdentity, err := verify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		t.Fatalf("identity policy: %v", err)
	}
	_, err = verifier.Verify(entity, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(artifact)),
		verify.WithCertificateIdentity(policyIdentity),
	))
	if err == nil {
		t.Fatal("certificate expired at the observer timestamp must fail verification")
	}
}

func tamperBundle(t *testing.T, raw []byte, target string) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	switch target {
	case "signature":
		message, ok := document["messageSignature"].(map[string]any)
		if !ok {
			t.Fatal("fixture has no message signature")
		}
		message["signature"] = "MEUCIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiEAto6Ky2XB8Oz+ZoSPG4PJ87rsTz1dGXtWuy/589vWfPw="
	case "proof":
		material, ok := document["verificationMaterial"].(map[string]any)
		if !ok {
			t.Fatal("fixture has no verification material")
		}
		entries, ok := material["tlogEntries"].([]any)
		if !ok || len(entries) != 1 {
			t.Fatal("fixture has unexpected Rekor entries")
		}
		entry, ok := entries[0].(map[string]any)
		if !ok {
			t.Fatal("fixture Rekor entry is invalid")
		}
		proof, ok := entry["inclusionProof"].(map[string]any)
		if !ok {
			t.Fatal("fixture has no inclusion proof")
		}
		proof["rootHash"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	default:
		t.Fatalf("unknown tamper target %q", target)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode tampered fixture: %v", err)
	}
	return encoded
}

func newOfficialFixtureVerifier(t *testing.T) *Verifier {
	t.Helper()
	verifier, err := New(Config{
		TrustedRootJSON:  readFixture(t, "official-scaffolding.trusted-root.json"),
		TrustRootVersion: "sigstore-go-scaffolding-1",
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return verifier
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func assertCheck(t *testing.T, checks []domain.VerifyCheck, name, want string) {
	t.Helper()
	for _, check := range checks {
		if check.Name == name && check.Result == want {
			return
		}
	}
	t.Fatalf("check %s=%s not found in %#v", name, want, checks)
}
