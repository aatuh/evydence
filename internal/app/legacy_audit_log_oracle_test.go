package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type AuditLogFilter struct {
	SubjectType string
	SubjectID   string
	Since       *time.Time
	Limit       int
}

func (l *Ledger) ListAuditLog(ctx context.Context, actor domain.Actor, filter AuditLogFilter) ([]domain.AuditChainEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	subjectType, subjectID := strings.TrimSpace(filter.SubjectType), strings.TrimSpace(filter.SubjectID)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeAdmin, resourceRefs{}); err != nil {
		return nil, err
	}
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return nil, err
	}
	entries := l.chain[actor.TenantID]
	out := []domain.AuditChainEntry{}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if subjectType != "" && entry.SubjectType != subjectType {
			continue
		}
		if subjectID != "" && entry.SubjectID != subjectID {
			continue
		}
		if filter.Since != nil && entry.OccurredAt.Before(filter.Since.UTC()) {
			continue
		}
		out = append(out, entry)
		if len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}
