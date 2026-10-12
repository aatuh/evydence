package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewEvidenceVerificationAuthorizer() application.Authorizer {
	return verificationAuthorizer{family: evidenceVerificationFamily}
}

// NewSubjectVerificationAuthorizer accepts a dispatcher preflight and the
// closed child operations selected after current subject ownership resolution.
func NewSubjectVerificationAuthorizer() application.Authorizer {
	return verificationAuthorizer{family: subjectVerificationFamily}
}

type verificationFamily uint8

const (
	evidenceVerificationFamily verificationFamily = iota
	artifactVerificationFamily
	bundleVerificationFamily
	subjectVerificationFamily
)

type verificationAuthorizer struct{ family verificationFamily }

func (p verificationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if request.Scope != "" || request.ScopeOnly && request.TenantWide || !p.accepts(request.Action) {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if request.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	} else if request.TenantWide {
		evaluation = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: request.Action, Resources: request.Resources, Evaluation: evaluation})
}

func (p verificationAuthorizer) accepts(action authz.Action) bool {
	switch action {
	case authz.ActionEvidenceVerify, authz.ActionDSSEVerify, authz.ActionAuditChainVerify, authz.ActionMerkleBatchVerify,
		authz.ActionMerkleCheckpointVerify, authz.ActionReleaseManifestCheckpointVerify, authz.ActionBackupManifestVerify:
		return p.family == evidenceVerificationFamily || p.family == subjectVerificationFamily
	case authz.ActionCosignVerify:
		return p.family == artifactVerificationFamily
	case authz.ActionArtifactSignatureVerify:
		return p.family == artifactVerificationFamily || p.family == subjectVerificationFamily
	case authz.ActionReleaseBundleVerify:
		return p.family == bundleVerificationFamily || p.family == subjectVerificationFamily
	case authz.ActionSubjectVerificationDispatch:
		return p.family == subjectVerificationFamily
	default:
		return false
	}
}
