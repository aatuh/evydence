package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Binding configuration shares the provider mutation fence without widening
// the general identity repository or changing existing OIDC provider records.
type SAMLProviderBindingTransaction interface {
	SSOProviderWriteReader
	application.Authorizer
	application.AuditAppender
	ReadOwnedSAMLProviderBinding(context.Context, string, string) (identitydomain.SAMLProviderBinding, error)
	UpsertSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
}
type SAMLProviderBindingTransactions interface {
	ExecuteSAMLProviderBinding(context.Context, func(context.Context, SAMLProviderBindingTransaction) error) error
}
type SAMLProviderBindingCommandConfig struct {
	Transactions SAMLProviderBindingTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ConfigureSAMLProviderBindingInput struct{ Recipient, NameIDFormat string }
type SAMLProviderBindingCommands struct {
	config SAMLProviderBindingCommandConfig
}

func NewSAMLProviderBindingCommands(c SAMLProviderBindingCommandConfig) (*SAMLProviderBindingCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SAMLProviderBindingCommands{config: c}, nil
}
func (s *SAMLProviderBindingCommands) prepare(ctx context.Context, a identitydomain.Actor, id string) (string, error) {
	if s == nil || ctx == nil {
		return "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, membershipAuthorization()); err != nil {
		return "", err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) || !validAPIKeyText(id, 1024) {
		return "", ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", ErrValidation
	}
	return id, nil
}
func (s *SAMLProviderBindingCommands) execute(ctx context.Context, a identitydomain.Actor, fn func(context.Context, SAMLProviderBindingTransaction) error) error {
	err := s.config.Transactions.ExecuteSAMLProviderBinding(ctx, func(ctx context.Context, tx SAMLProviderBindingTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, membershipAuthorization()); err != nil {
			return err
		}
		if err := tx.LockSSOProviderCreation(ctx, a.TenantID); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	return ctx.Err()
}
func (s *SAMLProviderBindingCommands) preparedInput(ctx context.Context, a identitydomain.Actor, id string, in ConfigureSAMLProviderBindingInput) (string, ConfigureSAMLProviderBindingInput, error) {
	id, err := s.prepare(ctx, a, id)
	if err != nil {
		return "", in, err
	}
	in.Recipient, in.NameIDFormat, err = NormalizeSAMLBindingParameters(in.Recipient, in.NameIDFormat)
	return id, in, err
}
func (s *SAMLProviderBindingCommands) binding(ctx context.Context, tx SAMLProviderBindingTransaction, a identitydomain.Actor, id string, in ConfigureSAMLProviderBindingInput) (identitydomain.SAMLProviderBinding, error) {
	p, err := tx.ReadOwnedSSOProvider(ctx, a.TenantID, id)
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, err
	}
	if p.TenantID != a.TenantID || p.ID != id {
		return identitydomain.SAMLProviderBinding{}, ErrNotFound
	}
	at := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	b := identitydomain.SAMLProviderBinding{TenantID: a.TenantID, ProviderID: id, Provider: cloneSSOProvider(p), Recipient: in.Recipient, NameIDFormat: in.NameIDFormat, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: at}
	if !ValidSAMLProviderBinding(b) {
		return identitydomain.SAMLProviderBinding{}, ErrValidation
	}
	return b, nil
}

// AuthorizeConfigure is also the durable HTTP replay guard: it rechecks current
// tenant authority and provider ownership without configuration or audit writes.
func (s *SAMLProviderBindingCommands) AuthorizeConfigureSAMLProviderBinding(ctx context.Context, a identitydomain.Actor, id string, in ConfigureSAMLProviderBindingInput) error {
	id, in, err := s.preparedInput(ctx, a, id, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx SAMLProviderBindingTransaction) error {
		_, err := s.binding(ctx, tx, a, id, in)
		return err
	})
}
func (s *SAMLProviderBindingCommands) ConfigureSAMLProviderBinding(ctx context.Context, a identitydomain.Actor, id string, in ConfigureSAMLProviderBindingInput) (identitydomain.SAMLProviderBinding, error) {
	id, in, err := s.preparedInput(ctx, a, id, in)
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, err
	}
	var out identitydomain.SAMLProviderBinding
	err = s.execute(ctx, a, func(ctx context.Context, tx SAMLProviderBindingTransaction) error {
		var err error
		out, err = s.binding(ctx, tx, a, id, in)
		if err != nil {
			return err
		}
		hash, err := s.config.Hasher.Hash(struct {
			TenantID, ProviderID, Recipient, NameIDFormat, SchemaVersion string
			UpdatedAt                                                    time.Time
		}{out.TenantID, out.ProviderID, out.Recipient, out.NameIDFormat, out.SchemaVersion, out.UpdatedAt})
		if err != nil {
			return err
		}
		if err := tx.UpsertSAMLProviderBinding(ctx, cloneSAMLProviderBinding(out)); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sso_provider.saml_binding_configured", SubjectType: "sso_provider", SubjectID: id, ActorType: actorType(a), ActorID: actorID(a), PayloadHash: hash, OccurredAt: out.UpdatedAt}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, err
	}
	return cloneSAMLProviderBinding(out), nil
}
func (s *SAMLProviderBindingCommands) GetSAMLProviderBinding(ctx context.Context, a identitydomain.Actor, id string) (identitydomain.SAMLProviderBinding, error) {
	id, err := s.prepare(ctx, a, id)
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, err
	}
	var out identitydomain.SAMLProviderBinding
	err = s.execute(ctx, a, func(ctx context.Context, tx SAMLProviderBindingTransaction) error {
		var err error
		out, err = tx.ReadOwnedSAMLProviderBinding(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if out.TenantID != a.TenantID || out.ProviderID != id {
			return ErrNotFound
		}
		if !ValidSAMLProviderBinding(out) {
			return ErrValidation
		}
		return nil
	})
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, err
	}
	return cloneSAMLProviderBinding(out), nil
}
