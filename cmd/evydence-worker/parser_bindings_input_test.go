package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func workerFuzzDSSE(t testing.TB) ([]byte, []byte) {
	t.Helper()
	payload, err := os.ReadFile("../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "synthetic", "sig": "c3ludGhldGlj"}}})
	if err != nil {
		t.Fatal(err)
	}
	return envelope, payload
}

func TestWorkerAttestationRejectsDuplicateObjectKeys(t *testing.T) {
	baseline, payload := workerFuzzDSSE(t)
	if _, err := parseReplayedAttestation(baseline); err != nil {
		t.Fatal("structural baseline rejected", err)
	}
	statement := append([]byte(`{"_type":"https://in-toto.io/Statement/v1",`), payload[1:]...)
	var decoded map[string]any
	if err := json.Unmarshal(baseline, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["payload"] = base64.StdEncoding.EncodeToString(statement)
	changedStatement, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"envelope":         append([]byte(`{"payloadType":"application/vnd.in-toto+json",`), baseline[1:]...),
		"escaped envelope": append([]byte(`{"payload\u0054ype":"application/vnd.in-toto+json",`), baseline[1:]...),
		"statement":        changedStatement,
	} {
		t.Run(name, func(t *testing.T) {
			if !json.Valid(raw) {
				t.Fatal("duplicate-key vector must remain valid JSON")
			}
			if _, err := parseReplayedAttestation(raw); err == nil {
				t.Fatal("ambiguous attestation acquired a worker projection")
			}
		})
	}
}
