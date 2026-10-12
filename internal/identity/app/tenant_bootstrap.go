package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// TenantBootstrapWriter grants only the identity and audit writes required by
// the composition-owned initial tenant transaction. It cannot create signing
// keys or reach other identity workflows.
type TenantBootstrapWriter interface {
	application.AuditAppender
	InsertTenant(context.Context, identitydomain.Tenant) error
	InsertAPIKey(context.Context, identitydomain.APIKey) error
}

type TenantBootstrapConfig struct {
	Credentials CredentialManager
	Clock       application.Clock
	IDs         application.IDGenerator
}

type TenantBootstrapCommands struct{ config TenantBootstrapConfig }

func NewTenantBootstrapCommands(c TenantBootstrapConfig) (*TenantBootstrapCommands, error) {
	if c.Credentials == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &TenantBootstrapCommands{c}, nil
}

func normalizeTenantBootstrapInput(input BootstrapTenantInput) (BootstrapTenantInput, error) {
	if !validAPIKeyText(input.TenantName, 65536) {
		return input, ErrValidation
	}
	input.TenantName = strings.TrimSpace(input.TenantName)
	if input.TenantName == "" {
		return input, ErrValidation
	}
	if len(input.Scopes) == 0 {
		input.Scopes = []string{"*"}
	}
	key, err := normalizeAPIKeyCreateInput(CreateAPIKeyInput{Name: input.APIKeyName, Scopes: input.Scopes})
	if err != nil {
		return input, err
	}
	input.APIKeyName, input.Scopes = key.Name, key.Scopes
	return input, nil
}

// PrepareTenantBootstrap performs no writes. Its result is sensitive until the
// composition root commits identity and initial signing state together.
func (s *TenantBootstrapCommands) PrepareTenantBootstrap(ctx context.Context, input BootstrapTenantInput) (PreparedTenantBootstrap, error) {
	if err := contextError(ctx); err != nil {
		return PreparedTenantBootstrap{}, err
	}
	if s == nil {
		return PreparedTenantBootstrap{}, ErrValidation
	}
	input, err := normalizeTenantBootstrapInput(input)
	if err != nil {
		return PreparedTenantBootstrap{}, err
	}
	credential, err := s.config.Credentials.Generate()
	if err != nil {
		return PreparedTenantBootstrap{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	prepared := PreparedTenantBootstrap{
		Tenant: identitydomain.Tenant{ID: s.config.IDs.NewID("ten"), Name: input.TenantName, CreatedAt: now},
		Secret: credential.Secret,
	}
	prepared.APIKey = identitydomain.APIKey{ID: s.config.IDs.NewID("key"), TenantID: prepared.Tenant.ID, Name: input.APIKeyName, Prefix: credential.Prefix, Hash: credential.Hash, Scopes: append([]string(nil), input.Scopes...), CreatedAt: now}
	if !s.validPrepared(prepared) {
		return PreparedTenantBootstrap{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return PreparedTenantBootstrap{}, err
	}
	return prepared, nil
}

func (s *TenantBootstrapCommands) validPrepared(p PreparedTenantBootstrap) bool {
	ten, key := p.Tenant, p.APIKey
	in, err := normalizeTenantBootstrapInput(BootstrapTenantInput{TenantName: ten.Name, APIKeyName: key.Name, Scopes: key.Scopes})
	if err != nil || in.TenantName != ten.Name || in.APIKeyName != key.Name || !validAPIKeyID(ten.ID) || !validAPIKeyID(key.ID) || key.TenantID != ten.ID || ten.CreatedAt.IsZero() || !validAPIKeyTime(ten.CreatedAt) || !key.CreatedAt.Equal(ten.CreatedAt) || len(key.Scopes) == 0 || key.ExpiresAt != nil || key.RevokedAt != nil || key.LastUsedAt != nil {
		return false
	}
	if strings.TrimSpace(p.Secret) == "" || !validAPIKeyText(p.Secret, 4096) || strings.TrimSpace(key.Prefix) == "" || !validAPIKeyText(key.Prefix, 128) || strings.TrimSpace(key.Hash) == "" || !validAPIKeyText(key.Hash, 128) {
		return false
	}
	return s.config.Credentials.Prefix(p.Secret) == key.Prefix && s.config.Credentials.Equal(key.Hash, s.config.Credentials.Hash(p.Secret))
}

func (s *TenantBootstrapCommands) CommitTenantBootstrap(ctx context.Context, tx TenantBootstrapWriter, p PreparedTenantBootstrap) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if s == nil || tx == nil || !s.validPrepared(p) {
		return ErrValidation
	}
	if err := tx.InsertTenant(ctx, p.Tenant); err != nil {
		return err
	}
	key := cloneAPIKey(p.APIKey)
	if err := tx.InsertAPIKey(ctx, key); err != nil {
		return err
	}
	id := s.config.IDs.NewID("ace")
	if !validAPIKeyID(id) {
		return ErrValidation
	}
	if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: id, TenantID: p.Tenant.ID, EntryType: "tenant.created", SubjectType: "tenant", SubjectID: p.Tenant.ID, ActorType: "system", ActorID: "bootstrap", OccurredAt: p.Tenant.CreatedAt.UTC()}); err != nil {
		return err
	}
	return ctx.Err()
}

type serviceTenantBootstrapTransaction struct{ Transaction }

func (t serviceTenantBootstrapTransaction) InsertTenant(ctx context.Context, tenant identitydomain.Tenant) error {
	return t.Identity().InsertTenant(ctx, tenant)
}
func (t serviceTenantBootstrapTransaction) InsertAPIKey(ctx context.Context, key identitydomain.APIKey) error {
	return t.Identity().InsertAPIKey(ctx, key)
}
func (t serviceTenantBootstrapTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.Audit().AppendAudit(ctx, event)
}
