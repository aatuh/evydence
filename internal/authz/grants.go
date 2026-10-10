package authz

import identitydomain "github.com/aatuh/evydence/internal/identity/domain"

// Only policy-selected, tenant-verified coordinates reach this evaluator.
// It is never used for instance authority, which requires an explicit scope.
func authorizeCurrentGrant(actor identitydomain.Actor, scope string, refs ResourceReferences, tenantWide bool) error {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if !grantHasCapability(grant, scope) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return nil
			}
		case "product":
			if !tenantWide && refs.ProductID != "" && grant.ResourceID == refs.ProductID {
				return nil
			}
		case "project":
			if !tenantWide && refs.ProjectID != "" && grant.ResourceID == refs.ProjectID {
				return nil
			}
		case "release":
			if !tenantWide && refs.ReleaseID != "" && grant.ResourceID == refs.ReleaseID {
				return nil
			}
		}
	}
	return ErrForbidden
}

func grantHasCapability(grant identitydomain.ResourceGrant, scope string) bool {
	for _, granted := range grant.Scopes {
		if granted == scope || granted == "admin" || granted == "*" {
			return true
		}
	}
	return false
}
