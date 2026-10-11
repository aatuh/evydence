package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Artifact scopes filter the association BEFORE its grant predicate. No
// artifact metadata or list of associations crosses this port.
type ControlEvidenceArtifactGrantRequest struct {
	TenantID, ArtifactID, ProductID, ReleaseID              string
	AllowedProductIDs, AllowedProjectIDs, AllowedReleaseIDs []string
}
type ControlEvidenceArtifactGrantReader interface {
	ControlEvidenceArtifactVisible(context.Context, ControlEvidenceArtifactGrantRequest) (bool, error)
}

func NewControlEvidenceWriteAuthorizer(reader ControlEvidenceArtifactGrantReader) (application.Authorizer, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return controlEvidenceWriteAuthorizer{reader}, nil
}

type controlEvidenceWriteAuthorizer struct {
	artifacts ControlEvidenceArtifactGrantReader
}

func (a controlEvidenceWriteAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Action != authz.ActionControlEvidenceLink || r.Scope != "" || r.ScopeOnly && r.TenantWide {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if r.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	} else if r.TenantWide {
		evaluation = authz.TenantEvaluation
	}
	return authz.AuthorizeWithArtifactVisibility(ctx, actor, authz.Request{Action: r.Action, Resources: r.Resources, Evaluation: evaluation},
		authz.ArtifactVisibilityFunc(func(ctx context.Context, refs authz.ArtifactVisibilityRequest) (bool, error) {
			request := ControlEvidenceArtifactGrantRequest{
				TenantID: refs.TenantID, ArtifactID: refs.ArtifactID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID,
				AllowedProductIDs: refs.AllowedProductIDs, AllowedProjectIDs: refs.AllowedProjectIDs, AllowedReleaseIDs: refs.AllowedReleaseIDs,
			}
			if !ValidControlEvidenceArtifactGrantRequest(request) {
				return false, ErrValidation
			}
			return a.artifacts.ControlEvidenceArtifactVisible(ctx, request)
		}))
}

// ValidControlEvidenceArtifactGrantRequest also protects direct persistence
// port callers. Association filtering accepts at most 4096 grant identities
// and 64 KiB combined identity text, never an unbounded set of query arguments.
func ValidControlEvidenceArtifactGrantRequest(r ControlEvidenceArtifactGrantRequest) bool {
	if !validControlText(r.TenantID, 1024, true) || !validControlText(r.ArtifactID, 1024, true) || !validControlText(r.ProductID, 1024, false) || !validControlText(r.ReleaseID, 1024, false) {
		return false
	}
	count, bytes := 0, 0
	for _, ids := range [][]string{r.AllowedProductIDs, r.AllowedProjectIDs, r.AllowedReleaseIDs} {
		if len(ids) > 4096-count {
			return false
		}
		count += len(ids)
		for _, id := range ids {
			if !validControlText(id, 1024, true) || len(id) > 65536-bytes {
				return false
			}
			bytes += len(id)
		}
	}
	return count > 0
}
