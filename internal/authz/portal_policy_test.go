package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var portalTokenCases = []Action{"portal_packages.read", "portal_packages.download"}

func portalPolicyFixture(action Action) (PortalTokenGrant, PortalPackageRequest) {
	now := time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC)
	grant := PortalTokenGrant{TenantID: "tenant", AccessID: "access", PackageID: "package", ExpiresAt: now.Add(time.Hour), RequireNDA: true}
	refs := ResourceReferences{TenantID: "tenant", ProductID: "product", ReleaseID: "release", CustomerPackageID: "package"}
	request := PortalPackageRequest{Action: action, Scope: refs, Target: refs, ExpiresAt: now.Add(time.Hour), Now: now, NDAAccepted: true, NDAAcceptedBy: "Reviewer"}
	return grant, request
}

func TestPortalTokenPolicyAllowsOnlyConcreteBoundPackageActionsAndConsent(t *testing.T) {
	for _, action := range portalTokenCases {
		t.Run(string(action), func(t *testing.T) {
			grant, request := portalPolicyFixture(action)
			beforeGrant, beforeRequest := grant, request
			if err := AuthorizePortalPackage(t.Context(), grant, request); err != nil || grant != beforeGrant || request != beforeRequest {
				t.Fatal("valid bound package denied or policy mutated its input", err)
			}
			request.NDAAccepted = false
			if err := AuthorizePortalPackage(t.Context(), grant, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("required consent bypassed", err)
			}
			grant.NDAAccepted = true
			request.NDAAcceptedBy = ""
			if err := AuthorizePortalPackage(t.Context(), grant, request); err != nil {
				t.Fatal("existing accepted consent was lost", err)
			}
			grant.NDAAccepted, grant.RequireNDA = false, false
			if err := AuthorizePortalPackage(t.Context(), grant, request); err != nil {
				t.Fatal("optional consent was made mandatory", err)
			}
			grant.RequireNDA, request.NDAAccepted, request.NDAAcceptedBy = true, true, " \t "
			if err := AuthorizePortalPackage(t.Context(), grant, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("blank reviewer claim became consent", err)
			}
		})
	}
}

func TestPortalTokenPolicyRejectsCredentialExpiryRevocationAndScopePromotion(t *testing.T) {
	for _, action := range portalTokenCases {
		grant, request := portalPolicyFixture(action)
		for _, edit := range []func(*PortalTokenGrant){
			func(g *PortalTokenGrant) { g.TenantID = "" }, func(g *PortalTokenGrant) { g.AccessID = "" }, func(g *PortalTokenGrant) { g.PackageID = "" },
			func(g *PortalTokenGrant) { g.TenantID = " tenant " }, func(g *PortalTokenGrant) { g.PackageID = "package\x00" },
			func(g *PortalTokenGrant) { g.Revoked = true }, func(g *PortalTokenGrant) { g.ExpiresAt = request.Now }, func(g *PortalTokenGrant) { g.ExpiresAt = time.Time{} },
		} {
			bad := grant
			edit(&bad)
			if err := AuthorizePortalPackage(t.Context(), bad, request); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("invalid credential acquired package authority", action, err)
			}
		}
		for _, other := range []Action{"unregistered", ActionPortalAccessManage, ActionCustomerPackagesAccess, ActionInstanceSnapshotRead} {
			bad := request
			bad.Action = other
			if err := AuthorizePortalPackage(t.Context(), grant, bad); !errors.Is(err, ErrForbidden) {
				t.Fatal("package token acquired another use case", other, err)
			}
		}
		for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key", Scopes: []string{"*", "admin", "package:read"}}, {TenantID: "tenant", UserID: "user", ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}, Scopes: []string{"*"}}, {TenantID: "tenant", KeyID: "key", CollectorID: "collector", Scopes: []string{"*"}}} {
			if err := Authorize(t.Context(), actor, Request{Action: action}); !errors.Is(err, ErrForbidden) {
				t.Fatal("API actor substituted for a verified package token", err)
			}
		}
	}
}

func TestPortalTokenPolicyHidesForeignIncoherentExpiredAndBroadenedTargets(t *testing.T) {
	for _, action := range portalTokenCases {
		grant, request := portalPolicyFixture(action)
		for _, which := range []string{"scope", "target", "both"} {
			for i := 0; i < reflect.TypeOf(request.Scope).NumField(); i++ {
				bad := request
				if which != "target" {
					reflect.ValueOf(&bad.Scope).Elem().Field(i).SetString("foreign")
				}
				if which != "scope" {
					reflect.ValueOf(&bad.Target).Elem().Field(i).SetString("foreign")
				}
				// A coherent different product/release in the current package
				// scope is legitimate; the token is package-bound, not an old
				// cached product grant. Other dimensions cannot be broadened.
				field := reflect.TypeOf(request.Scope).Field(i).Name
				if which == "both" && (field == "ProductID" || field == "ReleaseID") {
					if err := AuthorizePortalPackage(t.Context(), grant, bad); err != nil {
						t.Fatal("coherent current ownership point denied", err)
					}
					continue
				}
				if err := AuthorizePortalPackage(t.Context(), grant, bad); !errors.Is(err, ErrNotFound) {
					t.Fatal("foreign or expanded package target not hidden", action, which, field, err)
				}
			}
		}
		request.ExpiresAt = request.Now
		if err := AuthorizePortalPackage(t.Context(), grant, request); !errors.Is(err, ErrNotFound) {
			t.Fatal("expired package accessible", err)
		}
		request.Scope, request.Target = ResourceReferences{}, ResourceReferences{}
		if err := AuthorizePortalPackage(t.Context(), grant, request); !errors.Is(err, ErrNotFound) {
			t.Fatal("token promoted to tenant inventory", err)
		}
	}
}

func TestPortalTokenPolicyPropagatesCancellationWithoutAuthority(t *testing.T) {
	grant, request := portalPolicyFixture(ActionPortalPackagesRead)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, check := range []func(context.Context) error{func(ctx context.Context) error { return CheckPortalTokenValidity(ctx, grant, request.Now) }, func(ctx context.Context) error { return AuthorizePortalPackage(ctx, grant, request) }} {
		if err := check(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled policy gave authority", err)
		}
		var missing context.Context
		if err := check(missing); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("missing context gave authority", err)
		}
	}
}
