package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

const MaxRetentionMarkerTextBytes = 64 << 10

type RetentionMarkerInput struct{ ScopeType, ScopeID, Reason, Owner string }
type RetentionOverrideInput struct {
	RetentionMarkerInput
	RetentionUntil time.Time
}
type RetentionMarkerScopeLocker interface {
	LockRetentionMarkerScope(context.Context, string, string, string) error
}
type RetentionMarkerTransaction interface {
	RetentionMarkerScopeLocker
	application.Authorizer
	application.AuditAppender
	InsertLegalHold(context.Context, operationsdomain.LegalHold) error
	InsertRetentionOverride(context.Context, operationsdomain.RetentionOverride) error
}
type RetentionMarkerTransactions interface {
	ExecuteRetentionMarker(context.Context, func(context.Context, RetentionMarkerTransaction) error) error
}
type RetentionMarkerConfig struct {
	Transactions RetentionMarkerTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type RetentionMarkerCommands struct{ config RetentionMarkerConfig }

func NewRetentionMarkerCommands(c RetentionMarkerConfig) (*RetentionMarkerCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &RetentionMarkerCommands{c}, nil
}

func markerText(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0) && strings.TrimSpace(v) != ""
}
func NormalizeRetentionMarkerScope(kind, id string) (string, string, error) {
	if !markerText(kind, 64) || !markerText(id, 1024) {
		return "", "", ErrValidation
	}
	kind, id = strings.TrimSpace(kind), strings.TrimSpace(id)
	switch kind {
	case "tenant", "product", "project", "release", "evidence":
		return kind, id, nil
	default:
		return "", "", ErrValidation
	}
}
func NormalizeRetentionMarkerInput(in RetentionMarkerInput) (RetentionMarkerInput, error) {
	kind, id, err := NormalizeRetentionMarkerScope(in.ScopeType, in.ScopeID)
	if err != nil || !markerText(in.Reason, MaxRetentionMarkerTextBytes) || !markerText(in.Owner, MaxRetentionMarkerTextBytes) {
		return RetentionMarkerInput{}, ErrValidation
	}
	return RetentionMarkerInput{ScopeType: kind, ScopeID: id, Reason: strings.TrimSpace(in.Reason), Owner: strings.TrimSpace(in.Owner)}, nil
}

// Shape validation is independent of wall time: historical completed replay
// must not expire merely because the recorded extension date has passed.
func NormalizeRetentionOverrideInput(in RetentionOverrideInput) (RetentionOverrideInput, error) {
	v, err := NormalizeRetentionMarkerInput(in.RetentionMarkerInput)
	if err != nil || in.RetentionUntil.IsZero() {
		return RetentionOverrideInput{}, ErrValidation
	}
	until := in.RetentionUntil.UTC()
	if until.Year() < 1 || until.Year() > 9999 {
		return RetentionOverrideInput{}, ErrValidation
	}
	return RetentionOverrideInput{RetentionMarkerInput: v, RetentionUntil: until}, nil
}

type retentionMarkerAuthorizer struct{}

func NewRetentionMarkerAuthorizer() application.Authorizer { return retentionMarkerAuthorizer{} }
func (retentionMarkerAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != "admin" || !r.TenantWide || r.ScopeOnly || r.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, a, "admin")
}

func (s *RetentionMarkerCommands) execute(ctx context.Context, a identitydomain.Actor, kind, id string, fn func(context.Context, RetentionMarkerTransaction) error) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !markerText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	r := application.AuthorizationRequest{Scope: "admin", TenantWide: true}
	if err := s.config.Authorizer.Authorize(ctx, a, r); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteRetentionMarker(ctx, func(ctx context.Context, tx RetentionMarkerTransaction) error {
		if err := tx.Authorize(ctx, a, r); err != nil {
			return err
		}
		if err := tx.LockRetentionMarkerScope(ctx, a.TenantID, kind, id); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}
func (s *RetentionMarkerCommands) AuthorizeRetentionMarker(ctx context.Context, a identitydomain.Actor, kind, id string) error {
	kind, id, err := NormalizeRetentionMarkerScope(kind, id)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, kind, id, func(context.Context, RetentionMarkerTransaction) error { return nil })
}
func (s *RetentionMarkerCommands) CreateLegalHold(ctx context.Context, a identitydomain.Actor, in RetentionMarkerInput) (operationsdomain.LegalHold, error) {
	in, err := NormalizeRetentionMarkerInput(in)
	if err != nil {
		return operationsdomain.LegalHold{}, err
	}
	var out operationsdomain.LegalHold
	err = s.execute(ctx, a, in.ScopeType, in.ScopeID, func(ctx context.Context, tx RetentionMarkerTransaction) error {
		at := s.config.Clock.Now().UTC()
		v := operationsdomain.LegalHold{ID: s.config.IDs.NewID("lh"), TenantID: a.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner, SchemaVersion: operationsdomain.LegalHoldSchemaVersion, CreatedAt: at}
		if err := tx.InsertLegalHold(ctx, v); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, s.audit(a, in, "legal_hold.created", at)); err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		return operationsdomain.LegalHold{}, err
	}
	return out, nil
}
func (s *RetentionMarkerCommands) CreateRetentionOverride(ctx context.Context, a identitydomain.Actor, in RetentionOverrideInput) (operationsdomain.RetentionOverride, error) {
	in, err := NormalizeRetentionOverrideInput(in)
	if err != nil {
		return operationsdomain.RetentionOverride{}, err
	}
	var out operationsdomain.RetentionOverride
	err = s.execute(ctx, a, in.ScopeType, in.ScopeID, func(ctx context.Context, tx RetentionMarkerTransaction) error {
		at := s.config.Clock.Now().UTC()
		if !in.RetentionUntil.After(at) {
			return ErrValidation
		}
		v := operationsdomain.RetentionOverride{ID: s.config.IDs.NewID("ro"), TenantID: a.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, RetentionUntil: in.RetentionUntil, Reason: in.Reason, Owner: in.Owner, SchemaVersion: operationsdomain.RetentionOverrideSchemaVersion, CreatedAt: at}
		if err := tx.InsertRetentionOverride(ctx, v); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, s.audit(a, in.RetentionMarkerInput, "retention_override.created", at)); err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		return operationsdomain.RetentionOverride{}, err
	}
	return out, nil
}
func (s *RetentionMarkerCommands) audit(a identitydomain.Actor, in RetentionMarkerInput, kind string, at time.Time) application.AuditEvent {
	actorType, actorID := "api_key", a.KeyID
	if a.CollectorID != "" {
		actorType, actorID = "collector", a.CollectorID
	} else if a.UserID != "" {
		actorType, actorID = "human_user", a.UserID
	}
	return application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: kind, SubjectType: in.ScopeType, SubjectID: in.ScopeID, ActorType: actorType, ActorID: actorID, OccurredAt: at}
}
