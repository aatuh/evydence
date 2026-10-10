package authz

import (
	"context"
	"errors"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Adapters expose only these safe sentinels, never actor or grant details.
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// ResourceReferences are resolved ownership coordinates, not untrusted claims.
// A tenant-wide action does not authorize a narrower resource operation. Until
// its resource policy is registered, supplying those coordinates fails closed.
type ResourceReferences struct {
	TenantID          string
	OrganizationID    string
	ProductID         string
	ProjectID         string
	ReleaseID         string
	ArtifactID        string
	BuildID           string
	DeploymentID      string
	EnvironmentID     string
	CustomerPackageID string
}

// Request selects a policy action and its already-resolved resource boundary.
// An absent tenant target means the authenticated actor's own tenant.
type Request struct {
	Action    Action
	Resources ResourceReferences
}

// Authorize evaluates current actor grants on every call. It does not cache
// authority, access storage, or replace tenant-filtered repository lookups.
func Authorize(ctx context.Context, actor identitydomain.Actor, request Request) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return ErrUnauthorized
	}
	definition, ok := DefinitionFor(request.Action)
	if !ok {
		return ErrForbidden
	}
	switch definition.Boundary {
	case InstanceBoundary:
		if request.Resources != (ResourceReferences{}) || !actor.HasExplicitScope(definition.Scope) {
			return ErrForbidden
		}
		return nil
	case TenantBoundary:
		resources := request.Resources
		if resources.TenantID != "" && resources.TenantID != actor.TenantID {
			return ErrForbidden
		}
		resources.TenantID = ""
		if resources != (ResourceReferences{}) {
			return ErrForbidden
		}
		if !actor.HasScope(definition.Scope) && !actor.HasScope("admin") {
			return ErrForbidden
		}
		// API keys and collector credentials are scoped by issuance. A human
		// session additionally needs a current grant over the whole tenant.
		if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
			return nil
		}
		for _, grant := range actor.ResourceGrants {
			if grant.ResourceType != "" && grant.ResourceType != "tenant" || grant.ResourceID != "" && grant.ResourceID != actor.TenantID {
				continue
			}
			for _, scope := range grant.Scopes {
				if scope == definition.Scope || scope == "admin" || scope == "*" {
					return nil
				}
			}
		}
		return ErrForbidden
	default:
		return ErrForbidden
	}
}
