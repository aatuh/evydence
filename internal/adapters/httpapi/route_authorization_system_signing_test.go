package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func addNativeSystemSigningAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct{ operation, path string }{
		{"health", "/v1/health"}, {"startup", "/v1/startup"}, {"ready", "/v1/ready"}, {"version", "/v1/version"}, {"openapi", "/v1/openapi.json"},
	} {
		cases[tc.operation] = func(t *testing.T) {
			f := newNativeAuthorizationFixture(t)
			before, err := f.factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			for _, authorization := range []string{"", "Bearer forged-credential"} {
				out := f.requestWithHeaders(t, tc.operation, http.MethodGet, tc.path, domain.Actor{}, nil, 200, map[string]string{"Authorization": authorization})
				var body map[string]json.RawMessage
				if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if tc.operation == "openapi" {
					if len(body["openapi"]) == 0 || len(body["paths"]) == 0 {
						t.Fatal("public API contract is incomplete")
					}
				} else if len(body["data"]) == 0 {
					t.Fatal("public probe returned no status/identity")
				}
				for _, private := range []string{f.owner.actor.TenantID, f.owner.actor.KeyID, f.owner.evidence.ID, f.foreign.evidence.ID, "secret_hash", "private_key", "forged-credential"} {
					if strings.Contains(out.Body.String(), private) {
						t.Fatal("public probe exposed private authority or resource metadata", tc.operation)
					}
				}
			}
			if tc.operation == "ready" {
				f.server.bindOperatorFixtureResources(operatorFixtureResources{checks: []operationsquery.ReadinessCheck{{Name: "database", FailureDetail: "operator-only detail", Check: func(context.Context) error { return errors.New("private-dependency-error") }}}})
				out := f.requestWithHeaders(t, tc.operation, http.MethodGet, tc.path, domain.Actor{}, nil, 503, map[string]string{"Authorization": ""})
				if dataField(t, out.Body.String(), "status") != "unavailable" || strings.Contains(out.Body.String(), "operator-only") || strings.Contains(out.Body.String(), "private-dependency") {
					t.Fatal("public readiness exposed privileged diagnostics")
				}
			}
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("public probe changed repository state", err)
			}
		}
	}
	for _, tc := range []struct{ operation, path string }{
		{"instanceAdminSnapshot", "/v1/admin/instance"}, {"readinessDiagnostics", "/v1/admin/readiness"},
	} {
		cases[tc.operation] = func(t *testing.T) {
			f := newNativeAuthorizationFixture(t)
			f.server.bindOperatorFixtureResources(operatorFixtureResources{checks: []operationsquery.ReadinessCheck{{Name: "database", FailureDetail: "operator-only detail", Check: func(context.Context) error { return errors.New("private-dependency-error") }}}})
			before, err := f.factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			for _, actor := range []domain.Actor{f.owner.actor, f.foreign.actor, {TenantID: f.owner.actor.TenantID, UserID: "tenant-admin", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: f.owner.actor.TenantID, Scopes: []string{"*"}}}}} {
				out := f.request(t, tc.operation, http.MethodGet, tc.path, actor, nil, 403)
				if strings.Contains(out.Body.String(), `"data"`) {
					t.Fatal("tenant admin acquired instance diagnostics")
				}
			}
			instance := f.owner.actor
			instance.Scopes = []string{"instance:admin"}
			out := f.request(t, tc.operation, http.MethodGet, tc.path, instance, nil, 200)
			if tc.operation == "instanceAdminSnapshot" {
				if dataMap(t, out.Body.String())["tenant_count"] != float64(2) {
					t.Fatal("instance projection omitted real tenants")
				}
			} else if !strings.Contains(out.Body.String(), "operator-only detail") {
				t.Fatal("explicit instance admin did not receive safe diagnostic detail")
			}
			if strings.Contains(out.Body.String(), "private-dependency-error") || strings.Contains(out.Body.String(), f.owner.evidence.ID) {
				t.Fatal("operator response exposed raw errors or evidence")
			}
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("instance read changed repository state", err)
			}
		}
	}
	cases["metrics"] = func(t *testing.T) {
		f := newNativeAuthorizationFixture(t)
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		denied := f.owner.actor
		denied.Scopes = nil
		f.request(t, "metrics", http.MethodGet, "/v1/metrics", denied, nil, 403)
		for _, actor := range []domain.Actor{f.owner.actor, f.foreign.actor} {
			actor = nativeOperationPrincipal(t, "metrics", actor)
			out := f.request(t, "metrics", http.MethodGet, "/v1/metrics", actor, nil, 200)
			data := dataMap(t, out.Body.String())
			if data["resource_counts"].(map[string]any)["evidence"] != float64(1) || data["outbox"] != nil {
				t.Fatal("tenant metrics widened counts or acquired instance outbox diagnostics")
			}
			if strings.Contains(out.Body.String(), f.owner.evidence.ID) || strings.Contains(out.Body.String(), f.foreign.evidence.ID) {
				t.Fatal("scalar metrics exposed evidence metadata")
			}
		}
		after, err := f.factory.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("metrics changed repository state", err)
		}
	}
	cases["listControlFrameworkTemplatePacks"] = func(t *testing.T) {
		f := newNativeAuthorizationFixture(t)
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		denied := f.owner.actor
		denied.Scopes = nil
		f.request(t, "listControlFrameworkTemplatePacks", http.MethodGet, "/v1/control-framework-template-packs", denied, nil, 403)
		owner := f.request(t, "listControlFrameworkTemplatePacks", http.MethodGet, "/v1/control-framework-template-packs", nativeOperationPrincipal(t, "listControlFrameworkTemplatePacks", f.owner.actor), nil, 200)
		foreign := f.request(t, "listControlFrameworkTemplatePacks", http.MethodGet, "/v1/control-framework-template-packs", nativeOperationPrincipal(t, "listControlFrameworkTemplatePacks", f.foreign.actor), nil, 200)
		var ownedData, foreignData struct {
			Data []domain.ControlFrameworkTemplatePack `json:"data"`
		}
		if err := json.Unmarshal(owner.Body.Bytes(), &ownedData); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(foreign.Body.Bytes(), &foreignData); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(owner.Body.String(), "evydence-cra-readiness") || !reflect.DeepEqual(ownedData, foreignData) {
			t.Fatal("static template catalog became tenant data")
		}
		after, err := f.factory.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("static catalog changed repository state", err)
		}
	}
	for _, tc := range []struct{ operation, path string }{
		{"listSigningKeys", "/v1/signing-keys"}, {"signingCustodyReviewReport", "/v1/reports/custody-review"},
	} {
		cases[tc.operation] = nativeReadAuthorizationCase(tc.operation, func(nativeAuthorizationFixture) string { return tc.path }, func(f nativeAuthorizationFixture) string { return f.owner.actor.TenantID }, 200)
	}
	retentionFixture := func(t *testing.T) nativeAuthorizationFixture {
		f := newNativeAuthorizationFixture(t)
		hold, err := (operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: f.ledger}}).CreateLegalHold(t.Context(), f.owner.actor, operationsapp.RetentionMarkerInput{ScopeType: "release", ScopeID: f.owner.release.ID, Reason: "Retain review evidence", Owner: "Security"})
		if err != nil {
			t.Fatal(err)
		}
		f.legalHold = domain.LegalHold(hold)
		return f
	}
	// A scoped retention report echoes the caller's selector even when no
	// records are visible. The protected data is the owned marker, not that ID.
	cases["retentionReport"] = nativeReadAuthorizationFixtureCase("retentionReport", retentionFixture, func(f nativeAuthorizationFixture) string {
		return "/v1/reports/retention?scope_type=release&scope_id=" + f.owner.release.ID
	}, func(f nativeAuthorizationFixture) string { return f.legalHold.ID }, 200)
	for _, tc := range []struct {
		operation, path, body string
		status                int
	}{
		{"rotateSigningKey", "/v1/signing-keys/rotate", `{"reason":"Scheduled"}`, 201},
		{"createSigningProvider", "/v1/signing-providers", `{"name":"KMS","type":"aws_kms","key_ref":"public-key-reference","encrypted":true}`, 201},
		{"createDSSETrustRoot", "/v1/dsse-trust-roots", `{"name":"Builder","key_id":"builder-key","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_predicate_types":["https://slsa.dev/provenance/v1"],"expected_builder_ids":["builder"],"required_claims":["builder_id"]}`, 201},
	} {
		cases[tc.operation] = nativeWriteAuthorizationCase(tc.operation, func(nativeAuthorizationFixture) (string, []byte) { return tc.path, []byte(tc.body) }, tc.status)
	}
	fixture := func(t *testing.T) nativeAuthorizationFixture {
		f := newNativeAuthorizationFixture(t)
		keys, err := listFixtureSigningKeys(t.Context(), f.ledger, f.owner.actor)
		if err != nil || len(keys) != 1 {
			t.Fatal("native signing fixture has no unique active key", err)
		}
		f.signingKey = keys[0]
		return f
	}
	cases["revokeSigningKey"] = nativeWriteAuthorizationFixtureCase("revokeSigningKey", fixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/signing-keys/" + f.signingKey.ID + "/revoke", []byte(`{"reason":"Incident","semantics":"compromised","historical_validity_policy":"invalidate_all"}`)
	}, 200, 404)
}
