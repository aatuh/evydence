package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func normalizeSSOTrustInput(in UpdateSSOProviderTrustMaterialInput, trust TrustMaterialValidator) (UpdateSSOProviderTrustMaterialInput, error) {
	var err error
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
func applySSOTrustInput(p identitydomain.SSOProvider, in UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	p = cloneSSOProvider(p)
	switch p.Type {
	case "oidc":
		if len(in.JWKS) == 0 || len(in.SAMLSigningCertificates) != 0 {
			return identitydomain.SSOProvider{}, ErrValidation
		}
		p.JWKS = cloneAnyMap(in.JWKS)
		p.SAMLSigningCertificates = nil
	case "saml":
		if len(in.SAMLSigningCertificates) == 0 || len(in.JWKS) != 0 {
			return identitydomain.SSOProvider{}, ErrValidation
		}
		p.JWKS = nil
		p.SAMLSigningCertificates = append([]string(nil), in.SAMLSigningCertificates...)
	default:
		return identitydomain.SSOProvider{}, ErrValidation
	}
	return p, nil
}
func ssoTrustHashInput(p identitydomain.SSOProvider, now time.Time) any {
	return struct {
		ProviderID   string         `json:"provider_id"`
		JWKS         map[string]any `json:"jwks,omitempty"`
		Certificates []string       `json:"saml_signing_certificates,omitempty"`
		UpdatedAt    string         `json:"updated_at"`
	}{p.ID, p.JWKS, p.SAMLSigningCertificates, now.Format(time.RFC3339Nano)}
}
func (s *SSOProviderCommands) prepareTrust(ctx context.Context, a identitydomain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) (string, UpdateSSOProviderTrustMaterialInput, error) {
	if err := s.authorizeActor(ctx, a); err != nil {
		return id, in, err
	}
	if !validAPIKeyText(id, 1024) {
		return id, in, ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return id, in, ErrValidation
	}
	in, err := normalizeSSOTrustInput(in, s.config.TrustMaterial)
	return id, in, err
}
func readOwnedSSOProvider(ctx context.Context, tx SSOProviderTransaction, tenant, id string) (identitydomain.SSOProvider, error) {
	p, err := tx.ReadOwnedSSOProvider(ctx, tenant, id)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if p.ID != id || p.TenantID != tenant {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	return cloneSSOProvider(p), nil
}
func (s *SSOProviderCommands) AuthorizeUpdateSSOProviderTrustMaterial(ctx context.Context, a identitydomain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) error {
	id, in, err := s.prepareTrust(ctx, a, id, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx SSOProviderTransaction) error {
		p, err := readOwnedSSOProvider(ctx, tx, a.TenantID, id)
		if err != nil {
			return err
		}
		_, err = applySSOTrustInput(p, in)
		return err
	})
}
func (s *SSOProviderCommands) UpdateSSOProviderTrustMaterial(ctx context.Context, a identitydomain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	id, in, err := s.prepareTrust(ctx, a, id, in)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	var out identitydomain.SSOProvider
	err = s.execute(ctx, a, func(ctx context.Context, tx SSOProviderTransaction) error {
		expected, err := readOwnedSSOProvider(ctx, tx, a.TenantID, id)
		if err != nil {
			return err
		}
		out, err = applySSOTrustInput(expected, in)
		if err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		out.TrustMaterialUpdatedAt = &now
		hash, err := s.config.Hasher.Hash(ssoTrustHashInput(out, now))
		if err != nil {
			return err
		}
		if err := tx.CompareAndSwapSSOProviderTrustMaterial(ctx, expected, cloneSSOProvider(out)); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sso_provider.trust_material_updated", SubjectType: "sso_provider", SubjectID: id, ActorType: actorType(a), ActorID: actorID(a), PayloadHash: hash, OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return cloneSSOProvider(out), nil
}
