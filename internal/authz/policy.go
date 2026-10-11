package authz

import (
	"context"
	"errors"
	"strings"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Adapters expose only these safe sentinels, never actor or grant details.
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// ResourceReferences are resolved ownership coordinates, not untrusted claims.
// A tenant-wide action does not authorize a narrower resource operation.
// Each registered resource action constrains its exact coordinate shape.
type ResourceReferences struct {
	TenantID          string `json:",omitempty"`
	OrganizationID    string `json:",omitempty"`
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
	Action     Action
	Resources  ResourceReferences
	Evaluation Evaluation
}

// Evaluation makes a scope preflight distinct from resolved resource authority
// and tenant inventory authority. Preflight cannot carry resource claims.
type Evaluation uint8

const (
	ResolvedEvaluation Evaluation = iota
	ScopeEvaluation
	TenantEvaluation
)

// Authorize evaluates current actor grants on every call. It does not cache
// authority, access storage, or replace tenant-filtered repository lookups.
func Authorize(ctx context.Context, actor identitydomain.Actor, request Request) error {
	return authorizeWithArtifactVisibility(ctx, actor, request, nil)
}

func authorizeWithArtifactVisibility(ctx context.Context, actor identitydomain.Actor, request Request, artifacts ArtifactVisibilityReader) error {
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
	if !ok || request.Evaluation > TenantEvaluation {
		return ErrForbidden
	}
	switch definition.Boundary {
	case SelfSessionBoundary:
		if request.Evaluation != ResolvedEvaluation || request.Resources != (ResourceReferences{}) || strings.TrimSpace(actor.UserID) == "" || strings.TrimSpace(actor.SessionID) == "" || actor.KeyID != "" || actor.CollectorID != "" {
			return ErrForbidden
		}
		return nil
	case InstanceBoundary:
		if request.Evaluation != ResolvedEvaluation || request.Resources != (ResourceReferences{}) || !actor.HasExplicitScope(definition.Scope) {
			return ErrForbidden
		}
		return nil
	case TenantBoundary:
		if request.Evaluation == ScopeEvaluation {
			return ErrForbidden
		}
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
		return authorizeCurrentGrant(actor, definition.Scope, ResourceReferences{}, true)
	case ResourceBoundary:
		if allowsArtifactVisibility(request.Action) && request.Evaluation == ResolvedEvaluation && request.Resources.ArtifactID != "" {
			return authorizeArtifact(ctx, actor, definition.Scope, request, artifacts)
		}
		return authorizeResource(actor, definition.Scope, request)
	case CredentialBoundary:
		if request.Evaluation != ResolvedEvaluation || request.Resources != (ResourceReferences{}) || !actor.HasScope(definition.Scope) && !actor.HasScope("admin") {
			return ErrForbidden
		}
		return nil
	default:
		return ErrForbidden
	}
}
