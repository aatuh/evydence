package localed25519

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestPayloadVerifierChecksExactBytesAndRejectsMalformedMaterial(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("sha256:manifest")
	key := base64.RawStdEncoding.EncodeToString(public)
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload))
	v := PayloadVerifier{}
	if !v.VerifyPayload(key, sig, payload) {
		t.Fatal("valid signature rejected")
	}
	for _, tc := range []struct {
		key, sig string
		payload  []byte
	}{{key, sig, []byte("tampered")}, {"invalid", sig, payload}, {base64.RawStdEncoding.EncodeToString([]byte{1}), sig, payload}, {key, "invalid", payload}, {key, base64.RawStdEncoding.EncodeToString([]byte{1}), payload}} {
		if v.VerifyPayload(tc.key, tc.sig, tc.payload) {
			t.Fatal("malformed signature accepted")
		}
	}
}
