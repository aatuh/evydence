package app

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type memorySAMLAssertionConsumption struct {
	RequestID  string
	ConsumedAt time.Time
	Proof      identitydomain.SAMLAssertionUse
}

func cloneMemorySAMLRequest(r identitydomain.SAMLAuthenticationRequest) identitydomain.SAMLAuthenticationRequest {
	if r.ConsumedAt != nil {
		at := *r.ConsumedAt
		r.ConsumedAt = &at
	}
	return r
}
func validMemorySAMLRequest(r identitydomain.SAMLAuthenticationRequest) bool {
	_, format, err := identityapp.NormalizeSAMLBindingParameters(r.Recipient, r.NameIDFormat)
	return err == nil && format == r.NameIDFormat && identitydomain.ValidSAMLID(r.ID) && memoryMembershipQueryText(r.TenantID, 1024) && memoryMembershipQueryText(r.ProviderID, 1024) && memoryMembershipQueryText(r.Issuer, 4096) && memoryMembershipQueryText(r.Audience, 4096) && len(r.TrustFingerprint) == 71 && strings.HasPrefix(r.TrustFingerprint, "sha256:") && memoryOIDCHash(r.TrustFingerprint[7:]) && memoryOIDCHash(r.StateHash)
}
func memorySAMLBinding(state *MemoryUnitOfWorkSnapshot, tenant, id string) (identitydomain.SAMLProviderBinding, error) {
	p, ok := state.SSOProviders[id]
	if !ok || p.TenantID != tenant {
		return identitydomain.SAMLProviderBinding{}, ErrNotFound
	}
	b, ok := state.SAMLProviderBindings[id]
	if !ok || b.TenantID != tenant || b.ProviderID != id {
		return identitydomain.SAMLProviderBinding{}, ErrNotFound
	}
	provider, err := cloneMemoryJSON(p)
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, ErrConflict
	}
	b.Provider = identitydomain.SSOProvider(provider)
	return b, nil
}
func (r memoryIdentityRepository) ReadOwnedSAMLProviderBinding(ctx context.Context, tenant, id string) (identitydomain.SAMLProviderBinding, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(tenant, 1024) || !memoryMembershipQueryText(id, 1024) {
		return identitydomain.SAMLProviderBinding{}, ErrValidation
	}
	var out identitydomain.SAMLProviderBinding
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memorySAMLBinding(s, tenant, id)
		return err
	})
	return out, err
}
func (r memoryIdentityRepository) SAMLProviderBindingByID(ctx context.Context, id string) (identitydomain.SAMLProviderBinding, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(id, 1024) {
		return identitydomain.SAMLProviderBinding{}, ErrValidation
	}
	var out identitydomain.SAMLProviderBinding
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.SSOProviders[id]
		if !ok {
			return ErrNotFound
		}
		var err error
		out, err = memorySAMLBinding(s, p.TenantID, id)
		return err
	})
	return out, err
}
func (r memoryIdentityRepository) UpsertSAMLProviderBinding(ctx context.Context, b identitydomain.SAMLProviderBinding) error {
	if ctx == nil || r.uow == nil || !identityapp.ValidSAMLProviderBinding(b) {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.SSOProviders[b.ProviderID]
		if !ok || p.TenantID != b.TenantID {
			return ErrNotFound
		}
		current := b
		provider, err := cloneMemoryJSON(p)
		if err != nil {
			return ErrConflict
		}
		current.Provider = identitydomain.SSOProvider(provider)
		want, err := identityapp.SAMLProviderTrustFingerprint(b)
		if err != nil {
			return ErrValidation
		}
		got, err := identityapp.SAMLProviderTrustFingerprint(current)
		if err != nil || got != want {
			return ErrConflict
		}
		if old, ok := s.SAMLProviderBindings[b.ProviderID]; ok && old.UpdatedAt.After(b.UpdatedAt) {
			return ErrConflict
		}
		b.Provider = current.Provider
		s.SAMLProviderBindings[b.ProviderID] = b
		return nil
	})
}
func (r memoryIdentityRepository) ValidateSAMLProviderBinding(ctx context.Context, b identitydomain.SAMLProviderBinding) error {
	current, err := r.ReadOwnedSAMLProviderBinding(ctx, b.TenantID, b.ProviderID)
	if err != nil {
		return err
	}
	if !identityapp.ValidSAMLProviderBinding(current) {
		return ErrUnauthorized
	}
	want, err := identityapp.SAMLProviderTrustFingerprint(b)
	if err != nil {
		return ErrValidation
	}
	got, err := identityapp.SAMLProviderTrustFingerprint(current)
	if err != nil || got != want {
		return ErrConflict
	}
	return nil
}
func memorySAMLRequestMatchesBinding(r identitydomain.SAMLAuthenticationRequest, b identitydomain.SAMLProviderBinding) bool {
	fp, err := identityapp.SAMLProviderTrustFingerprint(b)
	return err == nil && identityapp.ValidSAMLProviderBinding(b) && fp == r.TrustFingerprint && r.Issuer == b.Provider.Issuer && r.Audience == b.Provider.ClientID && r.Recipient == b.Recipient && r.NameIDFormat == b.NameIDFormat
}
func (r memoryIdentityRepository) InsertSAMLAuthenticationRequest(ctx context.Context, v identitydomain.SAMLAuthenticationRequest, at time.Time) error {
	if ctx == nil || r.uow == nil || !validMemorySAMLRequest(v) || !v.PendingAt(at) {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		b, err := memorySAMLBinding(s, v.TenantID, v.ProviderID)
		if err != nil {
			return err
		}
		if !memorySAMLRequestMatchesBinding(v, b) {
			return ErrConflict
		}
		for k, m := range s.SAMLAssertionConsumptions {
			if k[0] == v.TenantID && k[1] == v.ProviderID && !m.Proof.ExpiresAt.After(at) {
				delete(s.SAMLAssertionConsumptions, k)
			}
		}
		count := 0
		for id, old := range s.SAMLAuthenticationRequests {
			if old.TenantID == v.TenantID && old.ProviderID == v.ProviderID {
				retained := false
				for k, m := range s.SAMLAssertionConsumptions {
					retained = retained || k[0] == old.TenantID && k[1] == old.ProviderID && m.RequestID == old.ID
				}
				if !old.ExpiresAt.After(at) && !retained {
					delete(s.SAMLAuthenticationRequests, id)
					continue
				}
				count++
			}
			if id == v.ID || old.StateHash == v.StateHash {
				return ErrConflict
			}
		}
		if count >= identitydomain.MaximumSAMLAuthenticationRequestsPerProvider {
			return ErrRateLimited
		}
		s.SAMLAuthenticationRequests[v.ID] = cloneMemorySAMLRequest(v)
		return nil
	})
}
func (r memoryIdentityRepository) ReadSAMLAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.SAMLAuthenticationRequest, error) {
	if ctx == nil || r.uow == nil || !memoryMembershipQueryText(tenant, 1024) || !memoryMembershipQueryText(provider, 1024) || !identitydomain.ValidSAMLID(id) {
		return identitydomain.SAMLAuthenticationRequest{}, ErrValidation
	}
	var out identitydomain.SAMLAuthenticationRequest
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.SAMLAuthenticationRequests[id]
		if !ok || v.ID != id || v.TenantID != tenant || v.ProviderID != provider {
			return ErrNotFound
		}
		out = cloneMemorySAMLRequest(v)
		return nil
	})
	return out, err
}
func (r memoryIdentityRepository) ConsumeSAMLAuthenticationRequest(ctx context.Context, expected identitydomain.SAMLAuthenticationRequest, proof identitydomain.SAMLAssertionUse, clock application.Clock) (time.Time, error) {
	if ctx == nil || r.uow == nil || clock == nil || !validMemorySAMLRequest(expected) {
		return time.Time{}, ErrValidation
	}
	var consumed time.Time
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		b, err := memorySAMLBinding(s, expected.TenantID, expected.ProviderID)
		if err != nil {
			return err
		}
		if !memorySAMLRequestMatchesBinding(expected, b) {
			return ErrUnauthorized
		}
		v, ok := s.SAMLAuthenticationRequests[expected.ID]
		consumed = clock.Now().UTC().Truncate(time.Microsecond)
		key := [3]string{expected.TenantID, expected.ProviderID, proof.AssertionHash}
		_, used := s.SAMLAssertionConsumptions[key]
		if !ok || !reflect.DeepEqual(v, expected) || !v.PendingAt(consumed) || !proof.ValidAt(consumed) || proof.IssuedAt.Before(v.CreatedAt.Add(-time.Minute)) || used {
			return ErrUnauthorized
		}
		for k, m := range s.SAMLAssertionConsumptions {
			if k[0] == v.TenantID && k[1] == v.ProviderID && m.RequestID == v.ID {
				return ErrUnauthorized
			}
		}
		v.ConsumedAt = &consumed
		s.SAMLAuthenticationRequests[v.ID] = cloneMemorySAMLRequest(v)
		s.SAMLAssertionConsumptions[key] = memorySAMLAssertionConsumption{RequestID: v.ID, ConsumedAt: consumed, Proof: proof}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return consumed, nil
}
