package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical control readers; never production wiring.
func (l *Ledger) ListControlFrameworks(ctx context.Context, actor domain.Actor) ([]domain.ControlFramework, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeControlsRead, resourceRefs{}); err != nil {
		return nil, err
	}
	out := []domain.ControlFramework{}
	for _, framework := range l.frameworks {
		if framework.TenantID == actor.TenantID {
			out = append(out, framework)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slug == out[j].Slug {
			return out[i].Version < out[j].Version
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

func (l *Ledger) GetSecurityControl(ctx context.Context, actor domain.Actor, id string) (domain.SecurityControl, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecurityControl{}, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return domain.SecurityControl{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeControlsRead, resourceRefs{}); err != nil {
		return domain.SecurityControl{}, err
	}
	control, ok := l.controls[strings.TrimSpace(id)]
	if !ok || control.TenantID != actor.TenantID {
		return domain.SecurityControl{}, ErrNotFound
	}
	return control, nil
}
