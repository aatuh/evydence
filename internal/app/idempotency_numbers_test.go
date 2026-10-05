package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestIdempotencyReplayRedactionPreservesExactJSONNumbers(t *testing.T) {
	const numbers = `{"size":9007199254740993,"max":9223372036854775807,"min":-9223372036854775808,"decimal":0.12345678901234567890123456789,"nested":[9007199254740995]}`
	for _, redact := range []bool{false, true} {
		response := map[string]any{"manifest": json.RawMessage(numbers)}
		if redact {
			response["secret"] = "replay-private-number-canary"
		}
		safe, err := safeIdempotencyReplayResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(safe)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "replay-private-number-canary") || strings.Contains(string(body), `"secret"`) {
			t.Fatal("redaction weakened", string(body))
		}
		for _, number := range []string{"9007199254740993", "9223372036854775807", "-9223372036854775808", "0.12345678901234567890123456789", "9007199254740995"} {
			if !strings.Contains(string(body), number) {
				t.Fatal("exact JSON number changed during replay redaction", redact, number, string(body))
			}
		}
	}
}

func TestMemoryIdempotencyReplayAndSnapshotPreserveExactJSONNumbers(t *testing.T) {
	const numbers = `{"large":9007199254740993,"max":9223372036854775807,"min":-9223372036854775808,"decimal":0.12345678901234567890123456789,"nested":[9007199254740995]}`
	f := NewMemoryUnitOfWorkFactory()
	a := domain.Actor{TenantID: "tenant", KeyID: "caller"}
	seedIdempotencyTenant(t, f, a.TenantID)
	x := IdempotencyUnitOfWork{Transactions: f, Now: fixedNow}
	calls := 0
	for range 2 {
		status, response, err := x.WithBody(t.Context(), a, "POST", "/numbers", "same", []byte(`{}`), func(context.Context, Repositories) (int, any, error) {
			calls++
			return 200, map[string]any{"manifest": json.RawMessage(numbers)}, nil
		})
		if err != nil || status != 200 {
			t.Fatal(status, err)
		}
		body, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"9007199254740993", "9223372036854775807", "-9223372036854775808", "0.12345678901234567890123456789", "9007199254740995"} {
			if !strings.Contains(string(body), n) {
				t.Error("memory replay rounded exact number", n, string(body))
			}
		}
	}
	snapshot, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range snapshot.Idempotency {
		body, err := json.Marshal(record.Response)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "9007199254740993") || !strings.Contains(string(body), "0.12345678901234567890123456789") {
			t.Error("memory snapshot rounded stored response", string(body))
		}
	}
	if calls != 1 || len(snapshot.Idempotency) != 1 {
		t.Fatal("memory replay duplicated effects", calls, len(snapshot.Idempotency))
	}
}
