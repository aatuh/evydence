package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (l *Ledger) authorizeStateTransition(ctx context.Context, a domain.Actor, id string, candidate bool) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeReleaseWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	id, err := releaseapp.NormalizeTransitionID(id)
	if err != nil {
		return fromReleaseContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	if candidate {
		v, ok := l.candidates[id]
		if !ok || v.TenantID != a.TenantID {
			return ErrNotFound
		}
		id = v.ReleaseID
	}
	r, ok := l.releases[id]
	if !ok || r.TenantID != a.TenantID {
		return ErrNotFound
	}
	p, ok := l.products[r.ProductID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	return l.authorizeResourceLocked(a, ScopeReleaseWrite, resourceRefs{ProductID: p.ID, ReleaseID: r.ID})
}
func (l *Ledger) AuthorizeReleaseTransition(ctx context.Context, a domain.Actor, id string) error {
	return l.authorizeStateTransition(ctx, a, id, false)
}
func (l *Ledger) AuthorizeCandidateTransition(ctx context.Context, a domain.Actor, id string) error {
	return l.authorizeStateTransition(ctx, a, id, true)
}
