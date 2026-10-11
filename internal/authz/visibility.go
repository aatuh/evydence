package authz

import (
	"context"
	"sort"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Visibility is an actor-derived storage filter, not caller-selected authority.
// Repositories apply these coordinates before pagination; services still verify
// returned row ownership and authorize each resolved resource.
type Visibility struct {
	TenantID   string
	TenantWide bool
	ProductIDs []string
	ProjectIDs []string
	ReleaseIDs []string
}

// ReadVisibility supports only registered read actions with explicit filtering
// rules. Current human grants are re-evaluated on every call, without a cache.
func ReadVisibility(ctx context.Context, actor identitydomain.Actor, action Action) (Visibility, error) {
	if err := Authorize(ctx, actor, Request{Action: action, Evaluation: ScopeEvaluation}); err != nil {
		return Visibility{}, err
	}
	switch action {
	case ActionEnvironmentsRead, ActionDeploymentsRead, ActionVulnerabilityDecisionsRead,
		ActionExceptionsRead, ActionControlEvidenceRead, ActionVulnerabilityDecisionSummaryRead,
		ActionReleaseReadinessRead, ActionReleaseSecuritySummaryRead:
	default:
		return Visibility{}, ErrForbidden
	}
	definition, _ := DefinitionFor(action) // Authorize already rejected unknown actions.
	return visibilityForGrants(actor, definition.Scope, action == ActionControlEvidenceRead, action != ActionEnvironmentsRead), nil
}

func visibilityForGrants(actor identitydomain.Actor, scope string, allowProjects, allowReleases bool) Visibility {
	visibility := Visibility{TenantID: actor.TenantID}
	if authorizeCurrentGrant(actor, scope, ResourceReferences{}, true) == nil {
		visibility.TenantWide = true
		return visibility
	}
	products := make(map[string]struct{})
	projects := make(map[string]struct{})
	releases := make(map[string]struct{})
	for _, grant := range actor.ResourceGrants {
		if grant.ResourceID == "" || !grantHasCapability(grant, scope) {
			continue
		}
		switch grant.ResourceType {
		case "product":
			products[grant.ResourceID] = struct{}{}
		case "release":
			if allowReleases {
				releases[grant.ResourceID] = struct{}{}
			}
		case "project":
			if allowProjects {
				projects[grant.ResourceID] = struct{}{}
			}
		}
	}
	for id := range products {
		visibility.ProductIDs = append(visibility.ProductIDs, id)
	}
	for id := range releases {
		visibility.ReleaseIDs = append(visibility.ReleaseIDs, id)
	}
	for id := range projects {
		visibility.ProjectIDs = append(visibility.ProjectIDs, id)
	}
	sort.Strings(visibility.ProductIDs)
	sort.Strings(visibility.ProjectIDs)
	sort.Strings(visibility.ReleaseIDs)
	return visibility
}
