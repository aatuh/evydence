package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Provider commands need a stable tenant and at most one owned provider,
// never a provider inventory. The tenant lock also serializes trust writes.
type SSOProviderWriteReader interface {
	LockSSOProviderCreation(context.Context, string) error
	ReadOwnedSSOProvider(context.Context, string, string) (identitydomain.SSOProvider, error)
}
type SSOProviderTransaction interface {
	SSOProviderWriteReader
	application.Authorizer
	application.AuditAppender
	InsertSSOProvider(context.Context, identitydomain.SSOProvider) error
	CompareAndSwapSSOProviderTrustMaterial(context.Context, identitydomain.SSOProvider, identitydomain.SSOProvider) error
}
type SSOProviderTransactions interface {
	ExecuteSSOProvider(context.Context, func(context.Context, SSOProviderTransaction) error) error
}
type SSOProviderCommandConfig struct {
	Transactions  SSOProviderTransactions
	Authorizer    application.Authorizer
	TrustMaterial TrustMaterialValidator
	Hasher        CanonicalHasher
	OIDCDiscovery OIDCDiscovery
	Clock         application.Clock
	IDs           application.IDGenerator
}
type SSOProviderCommands struct{ config SSOProviderCommandConfig }

func NewSSOProviderCommands(c SSOProviderCommandConfig) (*SSOProviderCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.TrustMaterial == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SSOProviderCommands{c}, nil
}

func normalizeSSOProviderInput(in CreateSSOProviderInput, trust TrustMaterialValidator) (CreateSSOProviderInput, error) {
	for _, text := range []string{in.Name, in.Issuer, in.ClientID, in.GroupsClaim} {
		if !validAPIKeyText(text, 65536) {
			return in, ErrValidation
		}
	}
	if !validAPIKeyText(in.Type, 128) {
		return in, ErrValidation
	}
	in.Name, in.Type, in.Issuer, in.ClientID, in.GroupsClaim = strings.TrimSpace(in.Name), strings.TrimSpace(in.Type), strings.TrimSpace(in.Issuer), strings.TrimSpace(in.ClientID), strings.TrimSpace(in.GroupsClaim)
	issuer, err := url.Parse(in.Issuer)
	if in.Name == "" || !validSSOType(in.Type) || in.ClientID == "" || err != nil || issuer.Scheme != "https" || issuer.Hostname() == "" || issuer.Opaque != "" || issuer.User != nil || issuer.Fragment != "" {
		return in, ErrValidation
	}
	for group, role := range in.RoleMapping {
		if !validAPIKeyText(group, 65536) || !validAPIKeyText(role, 65536) {
			return in, ErrValidation
		}
	}
	encoded, err := json.Marshal(in.RoleMapping)
	if err != nil || len(encoded) > 65536 {
		return in, ErrValidation
	}
	in.RoleMapping = cloneStringMap(in.RoleMapping)
	in.JWKS, err = trust.NormalizeJWKS(in.JWKS)
	if err != nil || !validSSOPublicKeyText(in.JWKS) {
		return in, ErrValidation
	}
	in.SAMLSigningCertificates, err = trust.NormalizeSAMLSigningCertificates(in.SAMLSigningCertificates)
	if err != nil {
		return in, ErrValidation
	}
	return in, nil
}

// The normalized public shape is shallow and bounded by the trust policy.
// PostgreSQL JSONB cannot retain NUL strings, even in otherwise valid JSON.
func validSSOPublicKeyText(jwks map[string]any) bool {
	if len(jwks) == 0 {
		return true
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return false
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		for _, value := range key {
			switch v := value.(type) {
			case string:
				if !validAPIKeyText(v, 65536) {
					return false
				}
			case []any:
				for _, item := range v {
					text, ok := item.(string)
					if !ok || !validAPIKeyText(text, 65536) {
						return false
					}
				}
			default:
				return false
			}
		}
	}
	return true
}
func (s *SSOProviderCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateSSOProviderInput) (CreateSSOProviderInput, error) {
	if err := s.authorizeActor(ctx, a); err != nil {
		return in, err
	}
	return normalizeSSOProviderInput(in, s.config.TrustMaterial)
}
func (s *SSOProviderCommands) authorizeActor(ctx context.Context, a identitydomain.Actor) error {
	if s == nil || ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, membershipAuthorization()); err != nil {
		return err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) {
		return ErrValidation
	}
	return nil
}
func (s *SSOProviderCommands) execute(ctx context.Context, a identitydomain.Actor, run func(context.Context, SSOProviderTransaction) error) error {
	return s.config.Transactions.ExecuteSSOProvider(ctx, func(ctx context.Context, tx SSOProviderTransaction) error {
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
		if err := run(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (s *SSOProviderCommands) AuthorizeCreateSSOProvider(ctx context.Context, a identitydomain.Actor, in CreateSSOProviderInput) error {
	if _, err := s.prepare(ctx, a, in); err != nil {
		return err
	}
	return s.execute(ctx, a, func(context.Context, SSOProviderTransaction) error { return nil })
}
func (s *SSOProviderCommands) CreateSSOProvider(ctx context.Context, a identitydomain.Actor, in CreateSSOProviderInput) (identitydomain.SSOProvider, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	var out identitydomain.SSOProvider
	err = s.execute(ctx, a, func(ctx context.Context, tx SSOProviderTransaction) error {
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		out = identitydomain.SSOProvider{ID: s.config.IDs.NewID("sso"), TenantID: a.TenantID, Name: in.Name, Type: in.Type, Issuer: in.Issuer, ClientID: in.ClientID, GroupsClaim: in.GroupsClaim, RoleMapping: in.RoleMapping, JWKS: in.JWKS, SAMLSigningCertificates: in.SAMLSigningCertificates, Status: "active", SchemaVersion: identitydomain.SSOProviderSchemaVersion, CreatedAt: now}
		if !validAPIKeyID(out.ID) {
			return ErrValidation
		}
		if err := tx.InsertSSOProvider(ctx, cloneSSOProvider(out)); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sso_provider.created", SubjectType: "sso_provider", SubjectID: out.ID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		_, err := tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return cloneSSOProvider(out), nil
}
