package authz

import identitydomain "github.com/aatuh/evydence/internal/identity/domain"

// Direct package grants are deliberately narrower than product/release grants.
// They authorize only access, portal management, and questionnaire association,
// never an unassociated evidence/answer/report selection or tenant inventory.
func authorizePackageGrant(actor identitydomain.Actor, scope string, action Action, refs ResourceReferences) error {
	switch action {
	case ActionCustomerPackagesAccess, ActionPortalAccessManage, ActionQuestionnairePackagesCreate:
	default:
		return ErrForbidden
	}
	if refs.CustomerPackageID == "" {
		return ErrForbidden
	}
	for _, grant := range actor.ResourceGrants {
		if grant.ResourceType == "customer_security_package" && grant.ResourceID == refs.CustomerPackageID && grantHasCapability(grant, scope) {
			return nil
		}
	}
	return ErrForbidden
}
