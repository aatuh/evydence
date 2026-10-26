package dsse

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestDSSEEnvelopeRejectsDuplicateObjectKeys(t *testing.T) {
	payload, err := os.ReadFile("../../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	baseline := signedEnvelopeWithMessage(t, payload, private, []byte("synthetic ingestion-only signature"))
	if _, err := Parse(baseline); err != nil {
		t.Fatal("structural baseline rejected", err)
	}
	for name, raw := range map[string][]byte{
		"root":          append([]byte(`{"payloadType":"application/vnd.in-toto+json",`), baseline[1:]...),
		"escaped root":  append([]byte(`{"payload\u0054ype":"application/vnd.in-toto+json",`), baseline[1:]...),
		"signature key": []byte(strings.Replace(string(baseline), `"keyid":"root-1"`, `"keyid":"root-1","keyid":"ambiguous"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, baseline) || !json.Valid(raw) {
				t.Fatal("duplicate-key vector must remain valid JSON")
			}
			if _, err := Parse(raw); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("ambiguous DSSE envelope accepted: %v", err)
			}
		})
	}
}
