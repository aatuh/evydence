package authz

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

// PortalTokenGrant is current storage-owned authorization state. Token parsing,
// constant-time secret verification, counters and audit commits remain owned by
// the application/credential ports. No raw token or hash enters policy.
type PortalTokenGrant struct {
	TenantID, AccessID, PackageID string
	ExpiresAt                     time.Time
	Revoked                       bool
	RequireNDA, NDAAccepted       bool
}

// PortalPackageRequest binds a verified token to current locked ownership
// coordinates and a concrete use case. Scope is the resolved ownership point;
// Target is the package returned by storage, not a caller-selected target.
type PortalPackageRequest struct {
	Action        Action
	Scope, Target ResourceReferences
	ExpiresAt     time.Time
	Now           time.Time
	NDAAccepted   bool
	NDAAcceptedBy string
}

func validPortalPolicyID(id string) bool {
	return id != "" && len(id) <= 1024 && strings.TrimSpace(id) == id && utf8.ValidString(id) && !strings.ContainsRune(id, 0)
}

// CheckPortalTokenValidity also runs before a failed-secret counter can change.
// Expired/revoked credentials never acquire authority from consent or a scope.
func CheckPortalTokenValidity(ctx context.Context, grant PortalTokenGrant, now time.Time) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validPortalPolicyID(grant.TenantID) || !validPortalPolicyID(grant.AccessID) || !validPortalPolicyID(grant.PackageID) || grant.Revoked || now.IsZero() || !grant.ExpiresAt.After(now) {
		return ErrUnauthorized
	}
	return nil
}

// AuthorizePortalPackage requires the application to have verified the token
// secret first. It grants neither tenant inventory nor arbitrary-resource
// access. Foreign, incoherent and expired packages share the hidden 404 policy.
func AuthorizePortalPackage(ctx context.Context, grant PortalTokenGrant, request PortalPackageRequest) error {
	if err := CheckPortalTokenValidity(ctx, grant, request.Now); err != nil {
		return err
	}
	definition, ok := DefinitionFor(request.Action)
	if !ok || definition.Boundary != PackageTokenBoundary {
		return ErrForbidden
	}
	scope := request.Scope
	if !validPortalPolicyID(scope.ProductID) || !validPortalPolicyID(scope.ReleaseID) || scope != (ResourceReferences{TenantID: grant.TenantID, ProductID: scope.ProductID, ReleaseID: scope.ReleaseID, CustomerPackageID: grant.PackageID}) || request.Target != scope || !request.ExpiresAt.After(request.Now) {
		return ErrNotFound
	}
	if grant.RequireNDA && !grant.NDAAccepted && (!request.NDAAccepted || strings.TrimSpace(request.NDAAcceptedBy) == "") {
		return ErrForbidden
	}
	return nil
}
