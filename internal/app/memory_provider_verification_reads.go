package app

import (
	"context"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// One bounded owned link tuple, not user/profile/grant inventory. Missing
// links are explicit negative facts for the existing exchange snapshot fence.
func (r memoryIdentityRepository) IdentityLink(ctx context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	if !memoryMembershipQueryText(provider, 1024) || !memoryMembershipQueryText(subject, 65536) {
		return identitydomain.UserIdentityLink{}, false, ErrValidation
	}
	var out identitydomain.UserIdentityLink
	found := false
	err := r.membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		for key, v := range state.IdentityLinks {
			if v.TenantID != tenant || v.ProviderID != provider || v.Subject != subject {
				continue
			}
			if found || v.ID != key {
				return ErrConflict
			}
			for _, field := range []struct {
				value string
				limit int
			}{{v.ID, 1024}, {v.TenantID, 1024}, {v.UserID, 1024}, {v.ProviderID, 1024}, {v.Subject, 65536}, {v.Email, 65536}, {v.SchemaVersion, 1024}} {
				if !memoryMembershipText(field.value, field.limit) {
					return ErrConflict
				}
			}
			out = identitydomain.UserIdentityLink(v)
			out.CreatedAt = out.CreatedAt.UTC()
			found = true
		}
		return nil
	})
	if err != nil {
		return identitydomain.UserIdentityLink{}, false, err
	}
	return out, found, nil
}

var _ identityapp.ProviderVerificationReader = memoryIdentityRepository{}
