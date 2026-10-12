package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestReadinessSeparatesPublicAndInstanceDiagnostics(t *testing.T) {
	service := NewReadiness([]ReadinessCheck{{
		Name: " postgres ", Timeout: 10 * time.Millisecond,
		FailureDetail: "database connectivity is unavailable",
		Check: func(ctx context.Context) error {
			<-ctx.Done()
			return errors.New("postgres://user:top-secret@database.internal/evydence")
		},
	}, {
		Name: "postgres", Check: func(context.Context) error { t.Fatal("duplicate probe ran"); return nil },
	}})
	public, err := service.Public(t.Context())
	if err != nil || public["status"] != "unavailable" {
		t.Fatalf("public readiness=%#v err=%v", public, err)
	}
	body, _ := json.Marshal(public)
	for _, forbidden := range []string{"top-secret", "database.internal", "database connectivity"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("public readiness leaked %q: %s", forbidden, body)
		}
	}
	for _, actor := range []identitydomain.Actor{{}, {TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}}} {
		_, err := service.Operator(t.Context(), actor)
		if actor.TenantID == "" && !errors.Is(err, application.ErrUnauthorized) || actor.TenantID != "" && !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("actor=%#v err=%v", actor, err)
		}
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"instance:admin"}}
	diagnostics, err := service.Operator(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(diagnostics)
	if !strings.Contains(string(body), "database connectivity is unavailable") || strings.Contains(string(body), "top-secret") || strings.Count(string(body), `"name":"postgres"`) != 1 {
		t.Fatalf("unsafe or duplicate operator readiness: %s", body)
	}
}

func TestReadinessRejectsNilOrCanceledContext(t *testing.T) {
	service := NewReadiness(nil)
	var absent context.Context
	if _, err := service.Public(absent); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil context err=%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.Public(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context err=%v", err)
	}
}
