package httpapi

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/authz"
)

func TestEveryRegisteredRouteDeclaresAuthorizationPolicyContract(t *testing.T) {
	routes := (&Server{}).routeDefinitions()
	if len(routes) != 189 {
		t.Fatalf("route inventory changed: %d; review every new/removed policy contract", len(routes))
	}
	seen := map[string]bool{}
	for _, route := range routes {
		if seen[route.op.OperationID] {
			t.Fatal("duplicate operation in policy inventory", route.op.OperationID)
		}
		seen[route.op.OperationID] = true
		if _, ok := route.op.Extensions["x-evydence-authorization"]; !ok {
			t.Errorf("%s lacks explicit authorization policy metadata", route.op.OperationID)
		}
		policy, ok := route.op.Extensions[routeAuthorizationExtension].(routeAuthorizationPolicy)
		if !ok {
			t.Fatal("policy metadata is not structured", route.op.OperationID)
		}
		if err := validateRouteAuthorizationPolicy(route.op, policy); err != nil {
			t.Errorf("%s: %v", route.op.OperationID, err)
		}
	}
}

func TestPortalRoutesDeclareExactTokenActionOrPublicForm(t *testing.T) {
	for _, tc := range []struct {
		operation, mode string
		actions         []authz.Action
	}{
		{"accessCustomerPortalPackage", "package-token", []authz.Action{authz.ActionPortalPackagesRead}},
		{"customerPortalPackageView", "package-token", []authz.Action{authz.ActionPortalPackagesRead}},
		{"downloadCustomerPortalPackage", "package-token", []authz.Action{authz.ActionPortalPackagesDownload}},
		{"downloadCustomerPortalPackageView", "package-token", []authz.Action{authz.ActionPortalPackagesDownload}},
		{"customerPortalPackageViewForm", "public-form", nil},
	} {
		p, ok := authorizationPolicyForOperation(tc.operation)
		if !ok || p.Mode != tc.mode || !slices.Equal(p.Actions, tc.actions) {
			t.Errorf("%s does not identify its actual public/token boundary: %#v", tc.operation, p)
		}
	}
}

func TestSignedIncidentRouteDeclaresItsConcreteReceiverAction(t *testing.T) {
	p, ok := authorizationPolicyForOperation("receiveIncidentWebhook")
	if !ok || p.Mode != "signed-webhook" || p.TenantRule != "verified-receiver-tenant" || !slices.Equal(p.Actions, []authz.Action{authz.ActionSignedIncidentWebhookRecord}) {
		t.Fatal("signed incident receiver lacks its concrete central action", p)
	}
}

func TestSSOExchangeRouteDeclaresItsConcreteVerifiedIdentityAction(t *testing.T) {
	p, ok := authorizationPolicyForOperation("exchangeSSOCredential")
	if !ok || p.Mode != "verified-sso-credential" || p.TenantRule != "verified-identity-tenant" || !slices.Equal(p.Actions, []authz.Action{authz.ActionSSOCredentialsExchange}) {
		t.Fatal("SSO exchange route lacks its concrete central action", p)
	}
}

func TestRouteAuthorizationContractsRejectDriftAndCannotBeMutatedThroughOtherRoutes(t *testing.T) {
	for _, route := range (&Server{}).routeDefinitions() {
		t.Run(route.op.OperationID, func(t *testing.T) {
			original := route.op.Extensions[routeAuthorizationExtension].(routeAuthorizationPolicy)
			for _, mutate := range []func(*routeAuthorizationPolicy){
				func(p *routeAuthorizationPolicy) { p.Mode = "" }, func(p *routeAuthorizationPolicy) { p.TenantRule = "" }, func(p *routeAuthorizationPolicy) { p.TenantRule = "wrong-resource" }, func(p *routeAuthorizationPolicy) { p.Mode = "unverified-caller" }, func(p *routeAuthorizationPolicy) {
					p.Actions = append(slices.Clone(p.Actions), authz.Action("unknown-action"))
				},
			} {
				bad := original
				bad.Actions = slices.Clone(original.Actions)
				mutate(&bad)
				if err := validateRouteAuthorizationPolicy(route.op, bad); err == nil {
					t.Fatal("invalid policy contract accepted", bad)
				}
			}
			badOp := route.op
			badOp.OperationID = "new-unmapped-operation"
			if err := validateRouteAuthorizationPolicy(badOp, original); err == nil {
				t.Fatal("new unmapped route inherited policy")
			}
			if original.Mode == "authenticated-principal" {
				badOp = route.op
				badOp.Scopes = []string{"unrelated-capability"}
				if err := validateRouteAuthorizationPolicy(badOp, original); err == nil {
					t.Fatal("OpenAPI scope drift accepted")
				}
				if route.op.OperationID == "metrics" {
					badOp = route.op
					badOp.Scopes = []string{"instance:admin"}
					if err := validateRouteAuthorizationPolicy(badOp, original); err == nil {
						t.Fatal("conditional instance capability replaced the published primary tenant scope")
					}
				}
				badOp = route.op
				badOp.Security = nil
				if err := validateRouteAuthorizationPolicy(badOp, original); err == nil {
					t.Fatal("bearer action lost authentication")
				}
				badOp = route.op
				badOp.Security = slices.Clone(route.op.Security)
				badOp.Security[0].Name = "UnrelatedAuthentication"
				if err := validateRouteAuthorizationPolicy(badOp, original); err == nil {
					t.Fatal("route substituted an unrelated authentication scheme")
				}
			} else {
				badOp = route.op
				badOp.Scopes = []string{"admin"}
				if err := validateRouteAuthorizationPolicy(badOp, original); err == nil {
					t.Fatal("public/token boundary borrowed bearer privilege")
				}
			}
			if len(original.Actions) > 0 {
				original.Actions[0] = authz.Action("mutated")
			}
			fresh, _ := authorizationPolicyForOperation(route.op.OperationID)
			if err := validateRouteAuthorizationPolicy(route.op, fresh); err != nil {
				t.Fatal("mutation escaped its metadata instance", err)
			}
		})
	}
}

func TestGeneratedOpenAPIPreservesEveryRouteAuthorizationContract(t *testing.T) {
	server, err := newLegacyServerFixture(newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "test"}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, route := range server.routeDefinitions() {
		var operation map[string]json.RawMessage
		if err := json.Unmarshal(document.Paths[route.path][strings.ToLower(route.method)], &operation); err != nil {
			t.Fatal("generated operation missing", route.op.OperationID, err)
		}
		var actual routeAuthorizationPolicy
		if err := json.Unmarshal(operation[routeAuthorizationExtension], &actual); err != nil {
			t.Fatal("policy metadata omitted from OpenAPI", route.op.OperationID, err)
		}
		if !reflect.DeepEqual(actual, route.op.Extensions[routeAuthorizationExtension]) {
			t.Fatal("generated policy contract drift", route.op.OperationID, actual)
		}
	}
}
