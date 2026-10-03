package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// APIKeyTransaction is a flat credential/audit boundary, not an identity
// service locator. The runner stabilizes the tenant through the same commit.
type APIKeyTransaction interface {
	application.Authorizer
	application.AuditAppender
	InsertAPIKey(context.Context, identitydomain.APIKey) error
}
type APIKeyTransactions interface {
	ExecuteAPIKey(context.Context, string, func(context.Context, APIKeyTransaction) error) error
}
type APIKeyWriteReader interface {
	LockAPIKeyCreation(context.Context, string) error
}
type APIKeyCredentials interface{ Generate() (Credential, error) }
type APIKeyCommandConfig struct {
	Transactions APIKeyTransactions
	Credentials  APIKeyCredentials
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type APIKeyCommands struct{ config APIKeyCommandConfig }

func NewAPIKeyCommands(c APIKeyCommandConfig) (*APIKeyCommands, error) {
	if c.Transactions == nil || c.Credentials == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &APIKeyCommands{c}, nil
}

type apiKeyWriteAuthorizer struct{}

func NewAPIKeyWriteAuthorizer() application.Authorizer { return apiKeyWriteAuthorizer{} }
func (apiKeyWriteAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeAdmin || r.ScopeOnly || !r.TenantWide || r.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, a, ScopeAdmin)
}
func apiKeyAuthorization() application.AuthorizationRequest {
	return application.AuthorizationRequest{Scope: ScopeAdmin, TenantWide: true}
}

// AuthorizeAPIKeyScopes preserves the explicit instance authority rule.
// Tenant wildcard/admin authority is not instance-administration authority.
// Unknown, blank and duplicate scopes keep their historical inert semantics.
func AuthorizeAPIKeyScopes(a identitydomain.Actor, scopes []string) error {
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "instance:admin" && !a.HasExplicitScope("instance:admin") {
			return application.ErrForbidden
		}
	}
	return nil
}
func validAPIKeyText(v string, limit int) bool {
	return len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func validAPIKeyID(v string) bool {
	return v != "" && validAPIKeyText(v, 1024) && strings.TrimSpace(v) == v
}
func validAPIKeyTime(v time.Time) bool { return v.Year() >= 1 && v.Year() <= 9999 }
func normalizeAPIKeyCreateInput(in CreateAPIKeyInput) (CreateAPIKeyInput, error) {
	if !validAPIKeyText(in.Name, 65536) || len(in.Scopes) == 0 || len(in.Scopes) > 1024 {
		return in, ErrValidation
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return in, ErrValidation
	}
	for _, scope := range in.Scopes {
		if !validAPIKeyText(scope, 128) {
			return in, ErrValidation
		}
	}
	in.Scopes = sortedStrings(in.Scopes)
	if in.ExpiresAt != nil {
		v := in.ExpiresAt.UTC().Truncate(time.Microsecond)
		if !validAPIKeyTime(v) {
			return in, ErrValidation
		}
		in.ExpiresAt = &v
	}
	return in, nil
}
func (s *APIKeyCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateAPIKeyInput) (CreateAPIKeyInput, error) {
	if s == nil || ctx == nil {
		return in, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, apiKeyAuthorization()); err != nil {
		return in, err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) {
		return in, ErrValidation
	}
	in, err := normalizeAPIKeyCreateInput(in)
	if err != nil {
		return in, err
	}
	return in, AuthorizeAPIKeyScopes(a, in.Scopes)
}
func (s *APIKeyCommands) execute(ctx context.Context, a identitydomain.Actor, fn func(context.Context, APIKeyTransaction) error) error {
	return s.config.Transactions.ExecuteAPIKey(ctx, a.TenantID, func(ctx context.Context, tx APIKeyTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, apiKeyAuthorization()); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}

// The replay guard checks current authority without generating credentials or
// reading tenant inventories. It joins an existing idempotency transaction.
func (s *APIKeyCommands) AuthorizeCreateAPIKey(ctx context.Context, a identitydomain.Actor, in CreateAPIKeyInput) error {
	if _, err := s.prepare(ctx, a, in); err != nil {
		return err
	}
	return s.execute(ctx, a, func(context.Context, APIKeyTransaction) error { return nil })
}
func (s *APIKeyCommands) CreateAPIKey(ctx context.Context, a identitydomain.Actor, in CreateAPIKeyInput) (identitydomain.APIKey, string, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return identitydomain.APIKey{}, "", err
	}
	var key identitydomain.APIKey
	var secret string
	err = s.execute(ctx, a, func(ctx context.Context, tx APIKeyTransaction) error {
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		credential, err := s.config.Credentials.Generate()
		if err != nil {
			return err
		}
		if len(credential.Secret) != 47 || !strings.HasPrefix(credential.Secret, "evy_") || len(credential.Prefix) != 12 || credential.Secret[:12] != credential.Prefix || len(credential.Hash) != 64 {
			return ErrValidation
		}
		if raw, err := base64.RawURLEncoding.DecodeString(credential.Secret[4:]); err != nil || len(raw) != 32 {
			return ErrValidation
		}
		if hash, err := hex.DecodeString(credential.Hash); err != nil || len(hash) != 32 {
			return ErrValidation
		}
		key = identitydomain.APIKey{ID: s.config.IDs.NewID("key"), TenantID: a.TenantID, Name: in.Name, Prefix: credential.Prefix, Hash: credential.Hash, Scopes: append([]string(nil), in.Scopes...), CreatedAt: now, ExpiresAt: cloneTime(in.ExpiresAt)}
		if !validAPIKeyID(key.ID) {
			return ErrValidation
		}
		if err := tx.InsertAPIKey(ctx, cloneAPIKey(key)); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "api_key.created", SubjectType: "api_key", SubjectID: key.ID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		secret = credential.Secret
		return nil
	})
	if err != nil {
		return identitydomain.APIKey{}, "", err
	}
	key.Hash = ""
	return cloneAPIKey(key), secret, nil
}
