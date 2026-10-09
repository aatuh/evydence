package localed25519

import (
	"crypto/ed25519"
	"encoding/base64"
)

// PayloadVerifier checks an existing local signing receipt using public
// material only. Malformed public keys cannot reach ed25519.Verify and panic.
type PayloadVerifier struct{}

func (PayloadVerifier) VerifyPayload(publicKey, signature string, payload []byte) bool {
	if len(publicKey) > 128 || len(signature) > 128 {
		return false
	}
	public, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	value, err := base64.RawStdEncoding.DecodeString(signature)
	return err == nil && ed25519.Verify(ed25519.PublicKey(public), payload, value)
}
