package authz

import identitydomain "github.com/aatuh/evydence/internal/identity/domain"

// Direct package grants are deliberately narrower than product/release grants.
// They authorize only access, portal metadata/management, questionnaire
// association, and package-root citation summaries. They never broaden an
// unassociated selection, other report output, or tenant inventory.
func authorizePackageGrant(actor identitydomain.Actor, scope string, action Action, refs ResourceReferences) error {
	switch action {
	case ActionCustomerPackagesAccess, ActionPortalAccessRead, ActionPortalAccessManage, ActionQuestionnairePackagesCreate, ActionEvidenceSummariesCreate:
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
