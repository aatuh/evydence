package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

// Historical retention commands and helpers remain unchanged, test-only.
type CreateLegalHoldInput struct {
	ScopeType string
	ScopeID   string
	Reason    string
	Owner     string
}

type CreateRetentionOverrideInput struct {
	ScopeType      string
	ScopeID        string
	RetentionUntil time.Time
	Reason         string
	Owner          string
}

func (l *Ledger) CreateLegalHold(ctx context.Context, actor domain.Actor, in CreateLegalHoldInput) (domain.LegalHold, error) {
	if err := ctx.Err(); err != nil {
		return domain.LegalHold{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.LegalHold{}, err
	}
	normalized, normalizeErr := operationsapp.NormalizeRetentionMarkerInput(operationsapp.RetentionMarkerInput{ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner})
	if normalizeErr != nil {
		return domain.LegalHold{}, ErrValidation
	}
	in = CreateLegalHoldInput(normalized)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRetentionScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.LegalHold{}, err
	}
	hold := domain.LegalHold{ID: newID("lh"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner, SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Governance.InsertLegalHold(ctx, hold); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(hold.CreatedAt, actor.TenantID, "legal_hold.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.LegalHold{}, err
		}
		l.legalHolds[hold.ID] = hold
		l.publishCommittedAuditEntryLocked(entry)
		return hold, nil
	}
	l.legalHolds[hold.ID] = hold
	_, _ = l.appendChainLocked(actor.TenantID, "legal_hold.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.LegalHold{}, err
	}
	return hold, nil
}

func (l *Ledger) CreateRetentionOverride(ctx context.Context, actor domain.Actor, in CreateRetentionOverrideInput) (domain.RetentionOverride, error) {
	if err := ctx.Err(); err != nil {
		return domain.RetentionOverride{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.RetentionOverride{}, err
	}
	normalized, normalizeErr := operationsapp.NormalizeRetentionOverrideInput(operationsapp.RetentionOverrideInput{RetentionMarkerInput: operationsapp.RetentionMarkerInput{ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner}, RetentionUntil: in.RetentionUntil})
	if normalizeErr != nil || !normalized.RetentionUntil.After(l.now()) {
		return domain.RetentionOverride{}, ErrValidation
	}
	in = CreateRetentionOverrideInput{ScopeType: normalized.ScopeType, ScopeID: normalized.ScopeID, Reason: normalized.Reason, Owner: normalized.Owner, RetentionUntil: normalized.RetentionUntil}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRetentionScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.RetentionOverride{}, err
	}
	override := domain.RetentionOverride{ID: newID("ro"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, RetentionUntil: in.RetentionUntil.UTC(), Reason: in.Reason, Owner: in.Owner, SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Governance.InsertRetentionOverride(ctx, override); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(override.CreatedAt, actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.RetentionOverride{}, err
		}
		l.retentionOverrides[override.ID] = override
		l.publishCommittedAuditEntryLocked(entry)
		return override, nil
	}
	l.retentionOverrides[override.ID] = override
	_, _ = l.appendChainLocked(actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RetentionOverride{}, err
	}
	return override, nil
}

func (l *Ledger) ensureRetentionScopeLocked(tenantID, scopeType, scopeID string) error {
	switch scopeType {
	case "tenant":
		if tenant, ok := l.tenants[scopeID]; !ok || tenant.ID != tenantID {
			return ErrNotFound
		}
	case "product", "project", "release":
		return l.ensureScopeLocked(tenantID, ternary(scopeType == "product", scopeID, ""), ternary(scopeType == "project", scopeID, ""), ternary(scopeType == "release", scopeID, ""))
	case "evidence":
		item, ok := l.evidence[scopeID]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}
