package sigstore

import (
	"os"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

func FuzzSigstoreBundle(f *testing.F) {
	// SOURCE.md and the provenance catalog pin these upstream bytes. All
	// trust and Rekor material is supplied locally; no online fallback runs.
	trusted, err := os.ReadFile("testdata/official-scaffolding.trusted-root.json")
	if err != nil {
		f.Fatal(err)
	}
	baseline, err := os.ReadFile("testdata/official-othername.bundle.json")
	if err != nil {
		f.Fatal(err)
	}
	verifier, err := New(Config{TrustedRootJSON: trusted, TrustRootVersion: "sigstore-go-scaffolding-1"})
	if err != nil {
		f.Fatal(err)
	}
	request := Request{Bundle: baseline, ArtifactDigest: officialFixtureDigest, ExpectedIdentity: officialFixtureSAN, ExpectedIssuer: officialFixtureIssuer, Mode: VerificationModeKeyless, Offline: true}
	positive, err := verifier.VerifyCosign(f.Context(), request)
	if err != nil || !sigstoreFuzzPassed(positive) {
		f.Fatalf("official offline bundle rejected: %v", err)
	}
	for _, mode := range []uint8{0, 1, 2, 3, 4, 5} {
		f.Add(baseline, mode)
	}
	f.Add([]byte(`{}`), uint8(0))
	f.Add([]byte(`{"mediaType":"not-a-bundle"}`), uint8(1))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 64<<10 || jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 64, MaxArrayItems: 64, MaxStringBytes: 32 << 10}) != nil {
			return
		}
		candidate := request
		candidate.Bundle = raw
		first, firstErr := verifier.VerifyCosign(t.Context(), candidate)
		again, againErr := verifier.VerifyCosign(t.Context(), candidate)
		if (firstErr == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) || (firstErr != nil && sigstoreFuzzPassed(first)) {
			t.Fatal("offline bundle decision is not stable or failed open")
		}
		unchanged, err := verifier.VerifyCosign(t.Context(), request)
		if err != nil || !reflect.DeepEqual(positive, unchanged) {
			t.Fatalf("unchanged official bundle lost trust: %v", err)
		}
		changed := request
		switch mode % 6 {
		case 0:
			changed.Bundle = tamperBundle(t, baseline, "signature")
		case 1:
			changed.Bundle = tamperBundle(t, baseline, "proof")
		case 2:
			changed.ArtifactDigest = "sha256:ac103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
		case 3:
			changed.ExpectedIdentity += "-different"
		case 4:
			changed.ExpectedIssuer = "https://issuer.example.invalid"
		case 5:
			changed.Offline = false
		}
		decision, err := verifier.VerifyCosign(t.Context(), changed)
		if err == nil || sigstoreFuzzPassed(decision) {
			t.Fatal("tampered bundle, subject/identity policy or online-required profile passed")
		}
	})
}

func sigstoreFuzzPassed(receipt Receipt) bool {
	if len(receipt.Checks) == 0 {
		return false
	}
	for _, check := range receipt.Checks {
		if check.Result != "passed" {
			return false
		}
	}
	return true
}
