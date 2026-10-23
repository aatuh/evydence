package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/health"
)

// ReadinessCheck is a bounded process dependency probe. FailureDetail must be
// a safe, operator-facing constant; raw probe errors are never returned.
type ReadinessCheck struct {
	Name          string
	Timeout       time.Duration
	FailureDetail string
	Check         func(context.Context) error
}

type Readiness struct {
	monitor *health.Monitor
	details map[string]string
}

func NewReadiness(checks []ReadinessCheck) (*Readiness, error) {
	return NewReadinessWithConfig(checks, health.Config{})
}

// NewReadinessWithConfig composes process health after runtime initialization.
// Database, schema and loaded configuration are startup prerequisites. Serving
// dependencies additionally gate readiness, without changing liveness.
func NewReadinessWithConfig(checks []ReadinessCheck, config health.Config) (*Readiness, error) {
	normalized := NormalizeReadinessChecks(checks)
	probes := make([]health.Check, 0, len(normalized))
	details := make(map[string]string, len(normalized))
	for _, check := range normalized {
		startup := check.Name == "postgres" || check.Name == "migrations" || check.Name == "configuration"
		probes = append(probes, health.Check{Name: check.Name, Startup: startup, Timeout: check.Timeout, Check: check.Check})
		details[check.Name] = check.FailureDetail
	}
	monitor, err := health.New(probes, config)
	if err != nil {
		return nil, fmt.Errorf("configure process health: %w", err)
	}
	monitor.MarkInitialized()
	return &Readiness{monitor: monitor, details: details}, nil
}

func NormalizeReadinessChecks(checks []ReadinessCheck) []ReadinessCheck {
	seen := map[string]struct{}{}
	normalized := make([]ReadinessCheck, 0, len(checks))
	for _, check := range checks {
		check.Name = strings.TrimSpace(check.Name)
		check.FailureDetail = strings.TrimSpace(check.FailureDetail)
		if check.Name == "" || check.Check == nil {
			continue
		}
		if _, duplicate := seen[check.Name]; duplicate {
			continue
		}
		if check.Timeout < 0 {
			check.Timeout = 0
		}
		if check.FailureDetail == "" {
			check.FailureDetail = "dependency check is unavailable"
		}
		seen[check.Name] = struct{}{}
		normalized = append(normalized, check)
	}
	return normalized
}

func (s *Readiness) snapshot(ctx context.Context) (health.Snapshot, error) {
	if s == nil || s.monitor == nil || ctx == nil {
		return health.Snapshot{}, ErrValidation
	}
	return s.monitor.Snapshot(ctx)
}

func (s *Readiness) Public(ctx context.Context) (map[string]any, error) {
	status, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return s.render(status, false), nil
}

func (s *Readiness) Startup(ctx context.Context) (map[string]any, error) {
	status, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": readinessState(status.StartupReady)}, nil
}

func (s *Readiness) Operator(ctx context.Context, actor identitydomain.Actor) (map[string]any, error) {
	if s == nil || ctx == nil {
		return nil, ErrValidation
	}
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionInstanceReadinessRead}); err != nil {
		return nil, err
	}
	status, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return s.render(status, true), nil
}

func (s *Readiness) MarkDraining() {
	if s != nil && s.monitor != nil {
		s.monitor.MarkDraining()
	}
}

func readinessState(ready bool) string {
	if ready {
		return "ok"
	}
	return "unavailable"
}

func (s *Readiness) render(status health.Snapshot, includeDetails bool) map[string]any {
	checks := make([]map[string]string, 0, len(status.Checks))
	for _, sampled := range status.Checks {
		check := map[string]string{"name": sampled.Name, "status": string(sampled.Status)}
		if includeDetails && sampled.Status != health.OK {
			check["detail"] = s.details[sampled.Name]
		}
		checks = append(checks, check)
	}
	result := map[string]any{"status": readinessState(status.Ready), "checks": checks}
	if includeDetails {
		result["startup_status"] = readinessState(status.StartupReady)
		result["initialized"] = status.Initialized
		result["draining"] = status.Draining
		if !status.CheckedAt.IsZero() {
			result["checked_at"] = status.CheckedAt.UTC().Format(time.RFC3339Nano)
			result["valid_until"] = status.ValidUntil.UTC().Format(time.RFC3339Nano)
		}
	}
	return result
}
