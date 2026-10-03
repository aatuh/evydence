package query

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
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
	checks []ReadinessCheck
}

func NewReadiness(checks []ReadinessCheck) *Readiness {
	return &Readiness{checks: NormalizeReadinessChecks(checks)}
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
		if check.Timeout <= 0 {
			check.Timeout = 3 * time.Second
		}
		if check.FailureDetail == "" {
			check.FailureDetail = "dependency check is unavailable"
		}
		seen[check.Name] = struct{}{}
		normalized = append(normalized, check)
	}
	return normalized
}

func (s *Readiness) Public(ctx context.Context) (map[string]any, error) {
	if s == nil || ctx == nil {
		return nil, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.status(ctx, false), nil
}

func (s *Readiness) Operator(ctx context.Context, actor identitydomain.Actor) (map[string]any, error) {
	if s == nil || ctx == nil {
		return nil, ErrValidation
	}
	if err := application.AuthorizeInstanceScope(ctx, actor, "instance:admin"); err != nil {
		return nil, err
	}
	return s.status(ctx, true), nil
}

func (s *Readiness) status(ctx context.Context, includeDetails bool) map[string]any {
	checks := []map[string]string{{"name": "ledger", "status": "ok"}}
	overall := "ok"
	for _, configured := range s.checks {
		checkCtx, cancel := context.WithTimeout(ctx, configured.Timeout)
		err := configured.Check(checkCtx)
		cancel()
		check := map[string]string{"name": configured.Name, "status": "ok"}
		if err != nil {
			check["status"] = "unavailable"
			overall = "unavailable"
			if includeDetails {
				check["detail"] = configured.FailureDetail
			}
		}
		checks = append(checks, check)
	}
	return map[string]any{"status": overall, "checks": checks}
}
