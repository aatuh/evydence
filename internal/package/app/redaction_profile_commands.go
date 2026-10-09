package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxRedactionProfileTextBytes  = 64 << 10
	MaxRedactionProfileEntryBytes = 1024
	MaxRedactionProfileEntries    = 1024
)

// Creation cannot read evidence, customer packages, signing material, or other
// profiles. Adapters fence the selected tenant before invoking the callback.
type RedactionProfileTransaction interface {
	InsertRedactionProfile(context.Context, packagedomain.RedactionProfile) error
	application.AuditAppender
}
type RedactionProfileTransactions interface {
	ExecuteRedactionProfile(context.Context, string, func(context.Context, RedactionProfileTransaction) error) error
}
type RedactionProfileCommandConfig struct {
	Transactions RedactionProfileTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type RedactionProfileCommands struct{ config RedactionProfileCommandConfig }

func NewRedactionProfileCommands(c RedactionProfileCommandConfig) (*RedactionProfileCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &RedactionProfileCommands{config: c}, nil
}

func redactionText(v string, limit int) bool {
	return len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func redactionID(v string) bool {
	return v != "" && v == strings.TrimSpace(v) && redactionText(v, MaxRedactionProfileEntryBytes)
}

// Check raw bounds before trimming, deduplicating, or allocating copies. The
// existing presets, sorting, and blank excluded-field behavior remain shared
// with the legacy Package service.
func NormalizeRedactionProfileInput(in CreateRedactionProfileInput) (CreateRedactionProfileInput, error) {
	if !redactionText(in.Name, MaxRedactionProfileTextBytes) || !redactionText(in.Description, MaxRedactionProfileTextBytes) || !redactionText(in.Preset, MaxRedactionProfileTextBytes) || len(in.AllowedTypes) > MaxRedactionProfileEntries || len(in.ExcludedFields) > MaxRedactionProfileEntries {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	for _, values := range [][]string{in.AllowedTypes, in.ExcludedFields} {
		for _, v := range values {
			if !redactionText(v, MaxRedactionProfileEntryBytes) {
				return CreateRedactionProfileInput{}, ErrValidation
			}
		}
	}
	normalized, err := normalizeRedactionProfileInput(in)
	// A preset has been expanded into its owned policy. Clearing the selector
	// makes normalization safe to repeat at transport and application boundaries.
	normalized.Preset = ""
	return normalized, err
}

func (s *RedactionProfileCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateRedactionProfileInput) (CreateRedactionProfileInput, error) {
	if s == nil {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return CreateRedactionProfileInput{}, err
	}
	if err := validateActor(a); err != nil {
		return CreateRedactionProfileInput{}, err
	}
	if !redactionID(a.TenantID) || !redactionID(auditActorID(a)) {
		return CreateRedactionProfileInput{}, ErrForbidden
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return CreateRedactionProfileInput{}, err
	}
	return NormalizeRedactionProfileInput(in)
}

// The durable executor invokes this before both fresh work and replay. It
// validates current authority and tenant existence without reading profile
// text, allocating IDs, or writing profile/audit effects.
func (s *RedactionProfileCommands) AuthorizeCreateRedactionProfile(ctx context.Context, a identitydomain.Actor, in CreateRedactionProfileInput) error {
	if _, err := s.prepare(ctx, a, in); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteRedactionProfile(ctx, a.TenantID, func(ctx context.Context, _ RedactionProfileTransaction) error { return contextError(ctx) })
}

func (s *RedactionProfileCommands) CreateRedactionProfile(ctx context.Context, a identitydomain.Actor, in CreateRedactionProfileInput) (packagedomain.RedactionProfile, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	var result packagedomain.RedactionProfile
	err = s.config.Transactions.ExecuteRedactionProfile(ctx, a.TenantID, func(ctx context.Context, tx RedactionProfileTransaction) error {
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		result = packagedomain.RedactionProfile{ID: s.config.IDs.NewID("rp"), TenantID: a.TenantID, Name: in.Name, Description: in.Description, AllowedTypes: in.AllowedTypes, ExcludedFields: in.ExcludedFields, SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: now}
		if err := ValidateRedactionProfileRecord(result); err != nil {
			return err
		}
		event := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "redaction_profile.created", SubjectType: "redaction_profile", SubjectID: result.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now}
		if !redactionID(event.ID) {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertRedactionProfile(ctx, cloneRedactionProfile(result)); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, event); err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	return cloneRedactionProfile(result), nil
}

// Reject noncanonical forged records instead of silently normalizing them at
// the database boundary. Historical response records are not revalidated.
func ValidateRedactionProfileRecord(v packagedomain.RedactionProfile) error {
	if !redactionID(v.ID) || !redactionID(v.TenantID) || v.SchemaVersion != packagedomain.RedactionProfileSchemaVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 {
		return ErrValidation
	}
	in, err := NormalizeRedactionProfileInput(CreateRedactionProfileInput{Name: v.Name, Description: v.Description, AllowedTypes: v.AllowedTypes, ExcludedFields: v.ExcludedFields})
	if err != nil || v.Name != in.Name || v.Description != in.Description || !slices.Equal(v.AllowedTypes, in.AllowedTypes) || !slices.Equal(v.ExcludedFields, in.ExcludedFields) {
		return ErrValidation
	}
	encoded, err := EncodeRedactionProfile(v)
	if err != nil || len(encoded) > MaxGeneratedReportBytes {
		return ErrValidation
	}
	return nil
}

// Keep the established snake_case shape and omitted empty optional fields.
func EncodeRedactionProfile(v packagedomain.RedactionProfile) ([]byte, error) {
	return json.Marshal(struct {
		ID             string    `json:"id"`
		TenantID       string    `json:"tenant_id"`
		Name           string    `json:"name"`
		Description    string    `json:"description,omitempty"`
		AllowedTypes   []string  `json:"allowed_types,omitempty"`
		ExcludedFields []string  `json:"excluded_fields,omitempty"`
		SchemaVersion  string    `json:"schema_version"`
		CreatedAt      time.Time `json:"created_at"`
	}{v.ID, v.TenantID, v.Name, v.Description, v.AllowedTypes, v.ExcludedFields, v.SchemaVersion, v.CreatedAt})
}

// The explicit local-memory facade delegates to the same command rules; only
// this adapter retains the old broad transaction port.
type serviceRedactionTransactions struct{ runner TransactionRunner }

func (t serviceRedactionTransactions) ExecuteRedactionProfile(ctx context.Context, _ string, fn func(context.Context, RedactionProfileTransaction) error) error {
	return t.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error { return fn(ctx, serviceRedactionTransaction{tx}) })
}

type serviceRedactionTransaction struct{ tx Transaction }

func (t serviceRedactionTransaction) InsertRedactionProfile(ctx context.Context, v packagedomain.RedactionProfile) error {
	return t.tx.Packages().InsertRedactionProfile(ctx, v)
}
func (t serviceRedactionTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, e)
}
