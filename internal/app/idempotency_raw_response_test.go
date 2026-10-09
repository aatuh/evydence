package app

import (
	"encoding/json"
	"testing"
)

func TestMemoryIdempotencyClonePreservesDetachedRawResponseOrderingAndExactNumbers(t *testing.T) {
	raw := json.RawMessage(`{"z":9007199254740993,"a":{"second":2,"first":1}}`)
	cloned, err := cloneMemoryIdempotencyRecord(IdempotencyRecord{Response: raw})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := cloned.Response.(json.RawMessage)
	if !ok || string(got) != string(raw) {
		t.Fatal("encoded replay response lost concrete type, field order or numeric precision", cloned.Response)
	}
	got[0] = '['
	if raw[0] != '{' {
		t.Fatal("raw response clone aliases caller bytes")
	}
	if _, err := cloneMemoryIdempotencyRecord(IdempotencyRecord{Response: json.RawMessage(`{"broken":`)}); err == nil {
		t.Fatal("malformed encoded replay response accepted")
	}
}
