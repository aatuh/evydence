package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestContextCorrelationRoundTripRejectsRawSecrets(t *testing.T) {
	var out bytes.Buffer
	l, err := New(&out, "api", testIdentity(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	root := WithLogger(t.Context(), l)
	ctx := WithOperation(WithRequest(root, "CANARY_REQUEST"), "createEvidence")
	c := CorrelationFromContext(ctx)
	if strings.Contains(c.RequestID, "CANARY") || c.RequestID == "" || c.OperationID == "" {
		t.Fatal("unsafe or missing correlation")
	}
	Emit(WithCorrelation(root, c), Command, Fields{Result: Succeeded})
	var r map[string]any
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r["request_id"] != c.RequestID || r["operation_id"] != c.OperationID {
		t.Fatal("durable round trip changed correlation")
	}
	if CorrelationFromContext(root) != (Correlation{}) {
		t.Fatal("context contaminated")
	}
	bad := WithCorrelation(root, Correlation{RequestID: "CANARY_SECRET", OperationID: "CANARY_SECRET"})
	if CorrelationFromContext(bad) != (Correlation{}) {
		t.Fatal("raw durable input accepted")
	}
	Emit(context.Background(), HTTPRequest, Fields{})
}

func TestProcessLogsExactIdentityAndNeverRawErrors(t *testing.T) {
	for _, rawError := range []error{nil, errors.New("CANARY_RAW_DATABASE_PROVIDER_BODY")} {
		t.Run(map[bool]string{true: "failure", false: "success"}[rawError != nil], func(t *testing.T) {
			var out bytes.Buffer
			err := Run(t.Context(), "worker", testIdentity(), &out, func(string) string { return "" }, func(ctx context.Context) error {
				if FromContext(ctx) == nil {
					t.Fatal("logger missing")
				}
				return rawError
			})
			if !errors.Is(err, rawError) {
				t.Fatal("process result changed")
			}
			if strings.Contains(out.String(), "CANARY") {
				t.Fatal("raw error leaked")
			}
			records := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(records) != 2 {
				t.Fatalf("lifecycle records=%d", len(records))
			}
			for i, line := range records {
				var r map[string]any
				if err := json.Unmarshal([]byte(line), &r); err != nil {
					t.Fatal(err)
				}
				if r["commit"] != testIdentity().Commit || r["version"] != testIdentity().Version {
					t.Fatal("missing exact build identity")
				}
				if i == 1 && rawError != nil && r["result_code"] != "failed" {
					t.Fatal("failure marked successful")
				}
			}
		})
	}
}

func TestInvalidLoggingConfigPreventsProcessSideEffects(t *testing.T) {
	var out bytes.Buffer
	called := false
	err := Run(t.Context(), "api", testIdentity(), &out, func(string) string { return "CANARY_SECRET" }, func(context.Context) error { called = true; return nil })
	if err == nil || called || strings.Contains(out.String(), "CANARY") || !strings.Contains(out.String(), "rejected") {
		t.Fatal("unsafe startup configuration handling")
	}
}

func TestDiagnosticWriterDiscardsRawRuntimeDetails(t *testing.T) {
	var out bytes.Buffer
	l, err := New(&out, "api", testIdentity(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	w := DiagnosticWriter(WithLogger(t.Context(), l))
	raw := []byte("CANARY_TOKEN_BODY_PANIC_DATABASE_URL\nsecond line")
	n, err := w.Write(raw)
	if n != len(raw) || err != nil || strings.Contains(out.String(), "CANARY") || strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), "uncertain") {
		t.Fatal("runtime diagnostic was lost or disclosed")
	}
}
