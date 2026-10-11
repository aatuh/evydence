package httpapi

import (
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func newNativeMembershipAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedMembershipFixtureScope(t, ledger, "Owner"), seedMembershipFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product}, operationsFixtureScope{actor: foreign.actor, product: foreign.product})
	f.membership = owner
	binding, err := (membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateRoleBinding(t.Context(), owner.actor, identityapp.CreateRoleBindingInput{SubjectType: "user", SubjectID: owner.user.ID, Role: "release_manager", ResourceType: "product", ResourceID: owner.product.ID})
	if err != nil {
		t.Fatal(err)
	}
	f.binding = domain.RoleBinding(binding)
	return f
}

func newNativeIntegrationAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedIntegrationFixtureScope(t, ledger, "Owner"), seedIntegrationFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product}, operationsFixtureScope{actor: foreign.actor, product: foreign.product})
	f.integration = owner
	_, err := (integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateCommercialCollectorDefinition(t.Context(), owner.actor, integrationapp.CreateCommercialCollectorInput{Name: "Existing scanner", Provider: "provider", Version: "1", ManifestHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AllowedScopes: []string{"evidence:write"}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func addNativeMembershipIntegrationAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation      string
		index, foreign int
	}{
		{"createOrganization", 0, 0}, {"createUser", 1, 404}, {"deactivateUser", 2, 404}, {"createRoleBinding", 3, 404},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeMembershipAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := membershipFixtureRequests(f.membership)[tc.index]
			return r.path, []byte(r.body)
		}, membershipFixtureRequests(membershipFixtureScope{})[tc.index].status, tc.foreign)
	}
	cases["listRoleBindings"] = nativeReadAuthorizationFixtureCase("listRoleBindings", newNativeMembershipAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/role-bindings" }, func(f nativeAuthorizationFixture) string { return f.binding.ID }, 200)
	cases["listAPIKeys"] = nativeReadAuthorizationCase("listAPIKeys", func(nativeAuthorizationFixture) string { return "/v1/api-keys" }, func(f nativeAuthorizationFixture) string { return f.owner.actor.KeyID }, 200)
	cases["listAuditLog"] = nativeReadAuthorizationCase("listAuditLog", func(nativeAuthorizationFixture) string { return "/v1/audit-log" }, func(f nativeAuthorizationFixture) string { return f.owner.product.ID }, 200)
	cases["createAPIKey"] = nativeMutationAuthorizationFixtureCase("createAPIKey", newNativeAuthorizationFixture, func(nativeAuthorizationFixture) (string, []byte) {
		return "/v1/api-keys", []byte(`{"name":"Reader","scopes":["evidence:read"]}`)
	}, nativeMutationExpectation{status: 201, resultField: "api_key", auditDelta: 1})
	for _, tc := range []struct {
		operation              string
		index, foreign, audits int
		field                  string
	}{
		{"createCollector", 0, 0, 1, "collector"},
		{"recordCollectorRelease", 1, 404, 1, ""},
		{"createCommercialCollector", 2, 0, 1, ""},
		{"createSourceRepository", 3, 404, 1, ""},
		{"recordSourceCommit", 4, 404, 1, ""},
		{"upsertSourceBranch", 5, 404, 1, ""},
		{"recordPullRequest", 6, 404, 1, ""},
		{"uploadGitHubSourceSnapshot", 7, 404, 4, "repository"},
		{"uploadGitLabSourceSnapshot", 8, 404, 4, "repository"},
	} {
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, newNativeIntegrationAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := integrationFixtureRequests(f.integration)[tc.index]
			return r.path, []byte(r.body)
		}, nativeMutationExpectation{status: 201, foreignStatus: tc.foreign, resultField: tc.field, auditDelta: tc.audits})
	}
	for _, tc := range []struct {
		operation, path string
		foreign         int
		contains        func(nativeAuthorizationFixture) string
	}{
		{"listCollectors", "/v1/collectors", 200, func(f nativeAuthorizationFixture) string { return f.integration.collector.ID }},
		{"collectorHealthReport", "/v1/collectors/", 404, func(f nativeAuthorizationFixture) string { return f.integration.collector.ID }},
		{"listCommercialCollectors", "/v1/commercial-collectors", 200, func(f nativeAuthorizationFixture) string { return f.owner.actor.TenantID }},
		{"listSourceRepositories", "/v1/source/repositories", 200, func(f nativeAuthorizationFixture) string { return f.integration.repository.ID }},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeIntegrationAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			if tc.operation == "collectorHealthReport" {
				return tc.path + f.integration.collector.ID + "/health"
			}
			return tc.path
		}, tc.contains, tc.foreign)
	}
}
