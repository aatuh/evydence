package app

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

func memoryAPIKeyTime(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	at := v.UTC()
	return &at
}

// Select public key metadata after tenant/keyset paging. The hash is never
// copied or validated by this read; it belongs only to authentication ports.
func (r memoryIdentityRepository) PageAPIKeys(ctx context.Context, req identityquery.APIKeyPageRequest) (appquery.Result[identitydomain.APIKey], error) {
	var out appquery.Result[identitydomain.APIKey]
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	type point struct {
		id string
		at time.Time
	}
	err := r.membershipRead(ctx, req.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		points := make([]point, 0)
		for id, key := range state.APIKeys {
			if key.TenantID != req.TenantID {
				continue
			}
			if key.ID != id || !memoryMembershipQueryText(id, 1024) || key.CreatedAt.IsZero() {
				return identityquery.ErrInvalidProjection
			}
			points = append(points, point{id, key.CreatedAt.UTC()})
		}
		page, err := appquery.Page(points, req.Page, req.After, func(p point, s appquery.Sort) appquery.SortKey { return appquery.RecordSortKey(p.id, p.at, s) })
		if err != nil {
			return err
		}
		out = appquery.Result[identitydomain.APIKey]{Items: make([]identitydomain.APIKey, 0, len(page.Items)), Next: page.Next}
		for _, p := range page.Items {
			key := state.APIKeys[p.id]
			if !memoryMembershipText(key.Name, 65536) || !memoryMembershipQueryText(key.Prefix, 12) || len(key.Scopes) == 0 {
				return identityquery.ErrInvalidProjection
			}
			scopes, err := json.Marshal(key.Scopes)
			if err != nil || len(scopes) > 1<<20 {
				return identityquery.ErrInvalidProjection
			}
			for _, scope := range key.Scopes {
				if !memoryMembershipText(scope, 128) {
					return identityquery.ErrInvalidProjection
				}
			}
			out.Items = append(out.Items, identitydomain.APIKey{ID: key.ID, TenantID: key.TenantID, Name: key.Name, Prefix: key.Prefix, Scopes: slices.Clone(key.Scopes), ExpiresAt: memoryAPIKeyTime(key.ExpiresAt), RevokedAt: memoryAPIKeyTime(key.RevokedAt), LastUsedAt: memoryAPIKeyTime(key.LastUsedAt), CreatedAt: key.CreatedAt.UTC()})
		}
		return nil
	})
	if err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	return out, nil
}

var _ identityquery.APIKeyReader = memoryIdentityRepository{}
