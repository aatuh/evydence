package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Check decoded provider text before JSON normalization can replace invalid
// UTF-8. Extensions remain ignored, but retained public fields must be safe.
func normalizeDiscoveredJWKS(result OIDCDiscoveryResult, expectedIssuer string, trust TrustMaterialValidator) (map[string]any, error) {
	if !validAPIKeyText(result.Issuer, 65536) || normalizedIssuer(result.Issuer) != normalizedIssuer(expectedIssuer) {
		return nil, ErrVerificationFailed
	}
	keys, ok := result.JWKS["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 10 {
		return nil, ErrVerificationFailed
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok {
			return nil, ErrVerificationFailed
		}
		public, err := projectPublicJWK(key)
		if err != nil || !validSSOPublicKeyText(map[string]any{"keys": []any{public}}) {
			return nil, ErrVerificationFailed
		}
	}
	jwks, err := trust.NormalizeJWKS(result.JWKS)
	if err != nil || len(jwks) == 0 || !validSSOPublicKeyText(jwks) {
		return nil, ErrVerificationFailed
	}
	return jwks, nil
}

func ssoDiscoveryHashInput(p identitydomain.SSOProvider, now time.Time) any {
	return struct {
		ProviderID string         `json:"provider_id"`
		Issuer     string         `json:"issuer"`
		JWKS       map[string]any `json:"jwks"`
		UpdatedAt  string         `json:"updated_at"`
	}{p.ID, p.Issuer, p.JWKS, now.Format(time.RFC3339Nano)}
}

func (s *SSOProviderCommands) prepareDiscovery(ctx context.Context, a identitydomain.Actor, id string) (string, error) {
	id, err := s.prepareProviderID(ctx, a, id)
	if err != nil {
		return id, err
	}
	if s.config.OIDCDiscovery == nil {
		return id, ErrValidation
	}
	return id, nil
}

func readOIDCProvider(ctx context.Context, tx SSOProviderTransaction, tenant, id string) (identitydomain.SSOProvider, error) {
	p, err := readOwnedSSOProvider(ctx, tx, tenant, id)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if p.Type != "oidc" {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	return p, nil
}

func (s *SSOProviderCommands) AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a identitydomain.Actor, id string) error {
	id, err := s.prepareDiscovery(ctx, a, id)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx SSOProviderTransaction) error {
		_, err := readOIDCProvider(ctx, tx, a.TenantID, id)
		return err
	})
}

func (s *SSOProviderCommands) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a identitydomain.Actor, id string) (identitydomain.SSOProvider, error) {
	id, err := s.prepareDiscovery(ctx, a, id)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	var out identitydomain.SSOProvider
	err = s.execute(ctx, a, func(ctx context.Context, tx SSOProviderTransaction) error {
		expected, err := readOIDCProvider(ctx, tx, a.TenantID, id)
		if err != nil {
			return err
		}
		result, err := s.config.OIDCDiscovery.FetchOIDCTrustMaterial(ctx, OIDCDiscoveryRequest{TenantID: a.TenantID, ProviderID: id, Issuer: expected.Issuer})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return ErrVerificationFailed
		}
		jwks, err := normalizeDiscoveredJWKS(result, expected.Issuer, s.config.TrustMaterial)
		if err != nil {
			return err
		}
		out, err = applySSOTrustInput(expected, UpdateSSOProviderTrustMaterialInput{JWKS: jwks})
		if err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		out.TrustMaterialUpdatedAt = &now
		hash, err := s.config.Hasher.Hash(ssoDiscoveryHashInput(out, now))
		if err != nil {
			return err
		}
		if err := tx.CompareAndSwapSSOProviderTrustMaterial(ctx, expected, cloneSSOProvider(out)); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sso_provider.oidc_trust_material_refreshed", SubjectType: "sso_provider", SubjectID: id, ActorType: actorType(a), ActorID: actorID(a), PayloadHash: hash, OccurredAt: now}
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
