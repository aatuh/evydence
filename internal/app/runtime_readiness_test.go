package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestReadinessRunsBoundedRequiredChecksWithoutLeakingProbeErrors(t *testing.T) {
	ledger := NewLedger(Config{ReadinessChecks: []ReadinessCheck{
		{
			Name:          "postgres",
			Timeout:       10 * time.Millisecond,
			FailureDetail: "database connectivity is unavailable",
			Check: func(ctx context.Context) error {
				<-ctx.Done()
				return errors.New("postgres://user:top-secret@database.internal/evydence is unavailable")
			},
		},
		{
			Name:          "signing_config",
			Timeout:       time.Second,
			FailureDetail: "required signing configuration is unavailable",
			Check:         func(context.Context) error { return nil },
		},
	}})

	started := time.Now()
	status, err := ledger.ReadinessStatus(context.Background())
	if err != nil {
		t.Fatalf("ReadinessStatus: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("readiness did not use the per-check timeout: %s", elapsed)
	}
	if status["status"] != "unavailable" {
		t.Fatalf("public readiness status = %#v, want unavailable", status)
	}
	publicBody := stringifyReadiness(status)
	if strings.Contains(publicBody, "top-secret") || strings.Contains(publicBody, "database.internal") || strings.Contains(publicBody, "database connectivity") {
		t.Fatalf("public readiness leaked probe detail: %s", publicBody)
	}

	actor := domain.Actor{TenantID: "ten_runtime", KeyID: "key_runtime", Scopes: []string{ScopeInstanceAdmin}}
	diagnostics, err := ledger.ReadinessDiagnostics(context.Background(), actor)
	if err != nil {
		t.Fatalf("ReadinessDiagnostics: %v", err)
	}
	diagnosticsBody := stringifyReadiness(diagnostics)
	if !strings.Contains(diagnosticsBody, "database connectivity is unavailable") {
		t.Fatalf("operator diagnostics missing safe check detail: %s", diagnosticsBody)
	}
	if strings.Contains(diagnosticsBody, "top-secret") || strings.Contains(diagnosticsBody, "database.internal") {
		t.Fatalf("operator diagnostics leaked probe error: %s", diagnosticsBody)
	}
	if _, err := ledger.ReadinessDiagnostics(context.Background(), domain.Actor{TenantID: "ten_runtime", KeyID: "key_runtime", Scopes: []string{"*"}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wildcard tenant administrator diagnostics err=%v, want forbidden", err)
	}
}

func stringifyReadiness(value map[string]any) string {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(body)
}
