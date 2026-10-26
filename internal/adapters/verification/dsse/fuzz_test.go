package dsse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

func FuzzDSSEEnvelope(f *testing.F) {
	payload, err := os.ReadFile("../../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		f.Fatal(err)
	}
	// Public, deterministic test material; never an operator signing key.
	seed := sha256.Sum256([]byte("Evydence EVY-1109 synthetic DSSE key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	policy := Policy{
		Roots:                 []TrustRoot{{ID: "dtr-1", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}},
		AllowedPredicateTypes: []string{testPredicate}, ExpectedBuilderIDs: []string{testBuilder},
		RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}, ExpectedSubjectDigests: []string{testSubject},
	}
	envelope := securedsse.Envelope{
		PayloadType: testPayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []securedsse.Signature{{KeyID: "root-1", Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(private, securedsse.PAE(testPayloadType, payload)))}},
	}
	baseline, err := json.Marshal(envelope)
	if err != nil {
		f.Fatal(err)
	}
	positive, err := Verify(f.Context(), baseline, policy)
	if err != nil || !positive.Passed() {
		f.Fatalf("signed in-toto positive vector rejected: %v", err)
	}
	for _, mode := range []uint8{0, 1, 2, 3} {
		f.Add(baseline, mode)
	}
	f.Add([]byte(`{}`), uint8(0))
	f.Add([]byte(`{"payloadType":"unknown","payload":"e30=","signatures":[]}`), uint8(1))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 64<<10 {
			return
		}
		limits := jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 64, MaxArrayItems: 64, MaxStringBytes: 32 << 10}
		if jsonbounds.Validate(raw, limits) != nil {
			return
		}
		var candidate securedsse.Envelope
		if json.Unmarshal(raw, &candidate) == nil {
			decoded, err := base64.StdEncoding.DecodeString(candidate.Payload)
			if err == nil && json.Valid(decoded) && jsonbounds.Validate(decoded, limits) != nil {
				return
			}
		}
		first, firstErr := Verify(t.Context(), raw, policy)
		again, againErr := Verify(t.Context(), raw, policy)
		if (firstErr == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) || (firstErr != nil && first.Passed()) {
			t.Fatal("DSSE verification decision is not stable or failed open")
		}
		unchanged, err := Verify(t.Context(), baseline, policy)
		if err != nil || !reflect.DeepEqual(positive, unchanged) {
			t.Fatalf("unchanged signed vector lost trust: %v", err)
		}
		// PAE binds the exact decoded payload and payload type, not the JSON
		// envelope's whitespace, key order or unsigned key-id hint.
		changed := envelope
		changed.Signatures = append([]securedsse.Signature(nil), envelope.Signatures...)
		changedPolicy := policy
		switch mode % 4 {
		case 0:
			changed.Payload = base64.StdEncoding.EncodeToString(append(append([]byte(nil), payload...), ' '))
		case 1:
			changed.PayloadType = "application/example+json"
		case 2:
			signature, err := base64.StdEncoding.DecodeString(changed.Signatures[0].Sig)
			if err != nil {
				t.Fatal(err)
			}
			signature[int(mode)%len(signature)] ^= 1
			changed.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
		case 3:
			changedPolicy.ExpectedSubjectDigests = []string{"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
		}
		tampered, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := Verify(t.Context(), tampered, changedPolicy)
		if err == nil && decision.Passed() {
			t.Fatal("tampered signed content or subject policy passed")
		}
	})
}
