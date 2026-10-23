package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/health"
)

func TestLifecycleReadinessSharesCacheSeparatesStartupAndRecovers(t *testing.T) {
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	var pending, objectOutage atomic.Bool
	objectOutage.Store(true)
	service, err := NewReadinessWithConfig([]ReadinessCheck{
		{Name: "migrations", FailureDetail: "database schema is unavailable", Check: func(context.Context) error {
			calls.Add(1)
			if pending.Load() {
				return errors.New("CANARY_PRIVATE_MIGRATION_PATH")
			}
			return nil
		}},
		{Name: "object_store", FailureDetail: "object store is unavailable", Check: func(context.Context) error {
			calls.Add(1)
			if objectOutage.Load() {
				return errors.New("https://CANARY_SECRET@storage.internal/private")
			}
			return nil
		}},
	}, health.Config{CacheTTL: time.Second, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	startup, err := service.Startup(t.Context())
	if err != nil || startup["status"] != "ok" || len(startup) != 1 {
		t.Fatal("optional serving dependency blocked or disclosed startup internals", startup, err)
	}
	public, err := service.Public(t.Context())
	if err != nil || public["status"] != "unavailable" || calls.Load() != 2 {
		t.Fatal("startup and readiness did not share one dependency snapshot", public, err, calls.Load())
	}
	checks, ok := public["checks"].([]map[string]string)
	if !ok || len(checks) != 2 {
		t.Fatal("public readiness includes a synthetic or omitted configured check", public)
	}
	for _, result := range []map[string]any{startup, public} {
		body, err := json.Marshal(result)
		if err != nil || strings.Contains(string(body), "CANARY") || strings.Contains(string(body), "storage.internal") || strings.Contains(string(body), "object store is unavailable") {
			t.Fatal("public lifecycle status disclosed private diagnostics", err)
		}
	}
	objectOutage.Store(false)
	at = at.Add(time.Second + time.Nanosecond)
	recovered, err := service.Public(t.Context())
	if err != nil || recovered["status"] != "ok" || calls.Load() != 4 {
		t.Fatal("restored serving dependency did not recover", recovered, err)
	}
	pending.Store(true)
	at = at.Add(time.Second + time.Nanosecond)
	startup, err = service.Startup(t.Context())
	if err != nil || startup["status"] != "unavailable" {
		t.Fatal("pending migrations did not block startup", startup, err)
	}
	public, err = service.Public(t.Context())
	if err != nil || public["status"] != "unavailable" || calls.Load() != 6 {
		t.Fatal("pending migrations did not block readiness using shared cache", public, err)
	}
	service.MarkDraining()
	public, err = service.Public(t.Context())
	if err != nil || public["status"] != "unavailable" || calls.Load() != 6 {
		t.Fatal("draining process performed new probes or admitted work", public, err)
	}
}

func TestLifecycleDiagnosticsAuthorizeBeforeProbeAndExposeOnlyVettedSnapshot(t *testing.T) {
	var calls atomic.Int32
	service, err := NewReadinessWithConfig([]ReadinessCheck{{Name: "postgres", FailureDetail: "database connectivity is unavailable", Check: func(context.Context) error {
		calls.Add(1)
		return errors.New("postgres://CANARY_SECRET@database.internal/private")
	}}}, health.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{{}, {TenantID: "tenant", KeyID: "tenant-admin", Scopes: []string{"*"}}} {
		_, err := service.Operator(t.Context(), actor)
		want := application.ErrForbidden
		if actor.TenantID == "" {
			want = application.ErrUnauthorized
		}
		if !errors.Is(err, want) || calls.Load() != 0 {
			t.Fatal("denied diagnostics ran instance probes or returned wrong authority result", err, calls.Load())
		}
	}
	instance := identitydomain.Actor{TenantID: "tenant", KeyID: "instance-admin", Scopes: []string{"instance:admin"}}
	diagnostics, err := service.Operator(t.Context(), instance)
	if err != nil || diagnostics["status"] != "unavailable" || diagnostics["startup_status"] != "unavailable" || diagnostics["initialized"] != true || diagnostics["draining"] != false || calls.Load() != 1 {
		t.Fatal("authorized diagnostics omitted lifecycle state", diagnostics, err)
	}
	for _, field := range []string{"checked_at", "valid_until"} {
		value, ok := diagnostics[field].(string)
		if !ok {
			t.Fatal("diagnostics omitted cache freshness", field)
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			t.Fatal("invalid diagnostic freshness timestamp", field, err)
		}
	}
	body, err := json.Marshal(diagnostics)
	if err != nil || !strings.Contains(string(body), "database connectivity is unavailable") || strings.Contains(string(body), "CANARY") || strings.Contains(string(body), "database.internal") {
		t.Fatal("diagnostics exposed provider errors or omitted vetted detail", err)
	}
	checks := diagnostics["checks"].([]map[string]string)
	checks[0]["detail"] = "CANARY_CALLER_MUTATION"
	again, err := service.Operator(t.Context(), instance)
	if err != nil || again["checks"].([]map[string]string)[0]["detail"] != "database connectivity is unavailable" || calls.Load() != 1 {
		t.Fatal("caller poisoned shared diagnostic cache", again, err)
	}
}

func TestLifecycleReadinessHonorsConfiguredDefaultDependencyDeadline(t *testing.T) {
	service, err := NewReadinessWithConfig([]ReadinessCheck{{Name: "postgres", Check: func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Millisecond {
			t.Error("readiness replaced the configured default probe timeout")
		}
		<-ctx.Done()
		return ctx.Err()
	}}}, health.Config{CheckTimeout: 10 * time.Millisecond, RefreshTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.Startup(t.Context())
	if err != nil || status["status"] != "unavailable" {
		t.Fatal("deadline did not block startup", status, err)
	}
}
