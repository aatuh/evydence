package app

import (
	"context"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

// Page only current owned role metadata. Memory selection mirrors keyset
// semantics but is not a PostgreSQL query/transfer/locking guarantee.
func (r memoryIdentityRepository) PageRoleBindings(ctx context.Context, req identityquery.RoleBindingPageRequest) (appquery.Result[identitydomain.RoleBinding], error) {
	var out appquery.Result[identitydomain.RoleBinding]
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	type point struct {
		id string
		at time.Time
	}
	err := r.membershipRead(ctx, req.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		points := make([]point, 0)
		for key, b := range state.RoleBindings {
			if b.TenantID != req.TenantID {
				continue
			}
			if b.ID != key || !memoryMembershipQueryText(b.ID, 1024) || b.CreatedAt.IsZero() {
				return identityquery.ErrInvalidProjection
			}
			points = append(points, point{b.ID, b.CreatedAt.UTC()})
		}
		page, err := appquery.Page(points, req.Page, req.After, func(p point, s appquery.Sort) appquery.SortKey { return appquery.RecordSortKey(p.id, p.at, s) })
		if err != nil {
			return err
		}
		out = appquery.Result[identitydomain.RoleBinding]{Items: make([]identitydomain.RoleBinding, 0, len(page.Items)), Next: page.Next}
		for _, p := range page.Items {
			b := state.RoleBindings[p.id]
			for _, field := range []struct {
				value string
				limit int
			}{{b.SubjectType, 128}, {b.SubjectID, 1024}, {b.Role, 128}, {b.ResourceType, 128}, {b.ResourceID, 1024}, {b.SchemaVersion, 1024}} {
				if !memoryMembershipText(field.value, field.limit) {
					return identityquery.ErrInvalidProjection
				}
			}
			if b.SubjectType == "" || b.SubjectID == "" || b.Role == "" || b.SchemaVersion == "" {
				return identityquery.ErrInvalidProjection
			}
			b.CreatedAt = b.CreatedAt.UTC()
			out.Items = append(out.Items, identitydomain.RoleBinding(b))
		}
		return nil
	})
	if err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	return out, nil
}

var _ identityquery.RoleBindingReader = memoryIdentityRepository{}
