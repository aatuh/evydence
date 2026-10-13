package app

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func cloneMemoryOIDCRequest(v identitydomain.OIDCAuthenticationRequest) identitydomain.OIDCAuthenticationRequest {
	if v.ConsumedAt != nil {
		at := *v.ConsumedAt
		v.ConsumedAt = &at
	}
	return v
}

func memoryOIDCHash(v string) bool {
	raw, err := hex.DecodeString(v)
	return err == nil && len(raw) == 32 && v == strings.ToLower(v)
}
func validMemoryOIDCRequest(v identitydomain.OIDCAuthenticationRequest) bool {
	return memoryMembershipQueryText(v.ID, 1024) && memoryMembershipQueryText(v.TenantID, 1024) && memoryMembershipQueryText(v.ProviderID, 1024) && len(v.TrustFingerprint) == 71 && strings.HasPrefix(v.TrustFingerprint, "sha256:") && memoryOIDCHash(v.TrustFingerprint[7:]) && memoryOIDCHash(v.StateHash) && memoryOIDCHash(v.NonceHash) && v.StateHash != v.NonceHash
}

func memoryOIDCProvider(state *MemoryUnitOfWorkSnapshot, tenant, id string) (identitydomain.SSOProvider, error) {
	p, ok := state.SSOProviders[id]
	if !ok || p.TenantID != tenant || p.ID != id {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	if p.Type != "oidc" || p.Status != "active" || p.Issuer == "" || p.ClientID == "" || len(p.JWKS) == 0 {
		return identitydomain.SSOProvider{}, ErrUnauthorized
	}
	return identitydomain.SSOProvider(p), nil
}
func (r memoryIdentityRepository) ValidateOIDCProvider(ctx context.Context, expected identitydomain.SSOProvider) error {
	if ctx == nil || r.uow == nil {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		p, err := memoryOIDCProvider(state, expected.TenantID, expected.ID)
		if err != nil {
			return err
		}
		want, err := identityapp.OIDCProviderTrustFingerprint(expected)
		if err != nil {
			return ErrValidation
		}
		got, err := identityapp.OIDCProviderTrustFingerprint(p)
		if err != nil || got != want {
			return ErrConflict
		}
		return nil
	})
}
func (r memoryIdentityRepository) InsertOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, at time.Time) error {
	if ctx == nil || r.uow == nil || !validMemoryOIDCRequest(v) || !v.PendingAt(at) {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		p, err := memoryOIDCProvider(state, v.TenantID, v.ProviderID)
		if err != nil {
			return err
		}
		fingerprint, err := identityapp.OIDCProviderTrustFingerprint(p)
		if err != nil || fingerprint != v.TrustFingerprint {
			return ErrConflict
		}
		count := 0
		for id, existing := range state.OIDCAuthenticationRequests {
			if existing.TenantID == v.TenantID && existing.ProviderID == v.ProviderID {
				if !existing.ExpiresAt.After(at) {
					delete(state.OIDCAuthenticationRequests, id)
					continue
				}
				count++
			}
			if id == v.ID || existing.StateHash == v.StateHash || existing.NonceHash == v.NonceHash {
				return ErrConflict
			}
		}
		if count >= identitydomain.MaximumOIDCAuthenticationRequestsPerProvider {
			return ErrRateLimited
		}
		state.OIDCAuthenticationRequests[v.ID] = cloneMemoryOIDCRequest(v)
		return nil
	})
}
func (r memoryIdentityRepository) ReadOIDCAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(tenant, 1024) || !memoryMembershipQueryText(provider, 1024) || !memoryMembershipQueryText(id, 1024) {
		return identitydomain.OIDCAuthenticationRequest{}, ErrValidation
	}
	var out identitydomain.OIDCAuthenticationRequest
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.OIDCAuthenticationRequests[id]
		if !ok || v.ID != id || v.TenantID != tenant || v.ProviderID != provider {
			return ErrNotFound
		}
		out = cloneMemoryOIDCRequest(v)
		return nil
	})
	return out, err
}
func (r memoryIdentityRepository) ConsumeOIDCAuthenticationRequest(ctx context.Context, expected identitydomain.OIDCAuthenticationRequest, clock application.Clock) (time.Time, error) {
	if ctx == nil || r.uow == nil || clock == nil || !validMemoryOIDCRequest(expected) {
		return time.Time{}, ErrValidation
	}
	var consumed time.Time
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		p, err := memoryOIDCProvider(state, expected.TenantID, expected.ProviderID)
		if err != nil {
			return err
		}
		fingerprint, err := identityapp.OIDCProviderTrustFingerprint(p)
		if err != nil || fingerprint != expected.TrustFingerprint {
			return ErrUnauthorized
		}
		v, ok := state.OIDCAuthenticationRequests[expected.ID]
		consumed = clock.Now().UTC().Truncate(time.Microsecond)
		if !ok || v.TenantID != expected.TenantID || v.ProviderID != expected.ProviderID || v.Delivery != expected.Delivery || v.TrustFingerprint != expected.TrustFingerprint || v.StateHash != expected.StateHash || v.NonceHash != expected.NonceHash || v.SchemaVersion != expected.SchemaVersion || !v.CreatedAt.Equal(expected.CreatedAt) || !v.ExpiresAt.Equal(expected.ExpiresAt) || !v.PendingAt(consumed) {
			return ErrUnauthorized
		}
		v.ConsumedAt = &consumed
		state.OIDCAuthenticationRequests[v.ID] = cloneMemoryOIDCRequest(v)
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return consumed, nil
}
