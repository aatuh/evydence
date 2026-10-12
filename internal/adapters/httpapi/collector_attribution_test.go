package httpapi

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestCollectorAttributionHTTPUsesAuthenticatedBindingForCreatesAndReplay(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "test", UnitOfWork: factory})
	clock := providerVerificationFixtureClock()
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("test"), clock}
	_, _, adminSecret, err := bootstrap.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	auth := fixtureIdentityAuthenticator(ledger, "test", clock)
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	s.bindCollectorFixtureResources("test", clock)
	admin, err := s.authn.Authenticate(t.Context(), adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := releaseSetup(ledger).CreateProduct(t.Context(), admin, "Product", "product")
	if err != nil {
		t.Fatal(err)
	}
	project, err := releaseSetup(ledger).CreateProject(t.Context(), admin, product.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	release, err := releaseSetup(ledger).CreateRelease(t.Context(), admin, product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	created := postJSON(t, s, adminSecret, "/v1/collectors", "collector", map[string]any{"name": "Builder", "type": "generic_ci", "version": "1", "scopes": []string{"evidence:write", "build:write"}}, 201)
	var credential struct {
		Data struct {
			Collector domain.Collector `json:"collector"`
			Secret    string           `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(created), &credential); err != nil || credential.Data.Collector.ID == "" || credential.Data.Secret == "" {
		t.Fatal("collector registration did not return a credential binding")
	}
	collectorID, collectorSecret := credential.Data.Collector.ID, credential.Data.Secret
	actor, err := s.authn.Authenticate(t.Context(), collectorSecret)
	if err != nil || actor.CollectorID != collectorID || actor.KeyID != credential.Data.Collector.APIKeyID || actor.TenantID != admin.TenantID {
		t.Fatal("issued token did not authenticate as its exact collector binding")
	}
	evidence := map[string]any{"product_id": product.ID, "type": "manual", "title": "Note", "payload_hash": "sha256:" + strings.Repeat("a", 64), "source_identity": map[string]any{"collector_id": collectorID, "job": "job"}}
	build := map[string]any{"project_id": project.ID, "release_id": release.ID, "provider": "generic_ci", "commit_sha": strings.Repeat("a", 40), "status": "passed", "started_at": "2026-10-02T12:00:00Z", "provider_metadata": map[string]any{"collector_id": collectorID, "job": "job"}}
	for _, tc := range []struct {
		path, key, metadataField string
		body                     map[string]any
	}{
		{"/v1/evidence", "evidence", "source_identity", evidence},
		{"/v1/builds", "build", "provider_metadata", build},
	} {
		t.Run(tc.key, func(t *testing.T) {
			one := postJSON(t, s, collectorSecret, tc.path, tc.key, tc.body, 201)
			assertTrustHTTPReplay(t, one, postJSON(t, s, collectorSecret, tc.path, tc.key, tc.body, 201))
			var response struct {
				Data struct {
					CollectorID    string         `json:"collector_id"`
					SourceIdentity map[string]any `json:"source_identity"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &response); err != nil || response.Data.CollectorID != collectorID || response.Data.SourceIdentity["collector_id"] != collectorID || response.Data.SourceIdentity["job"] != "job" {
				t.Fatal("create/replay response lost authenticated attribution or metadata")
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			for i, claim := range []any{"foreign-collector", " " + collectorID + " ", 42, nil, ""} {
				bad := make(map[string]any, len(tc.body))
				for k, v := range tc.body {
					bad[k] = v
				}
				bad[tc.metadataField] = map[string]any{"collector_id": claim}
				out := postJSON(t, s, collectorSecret, tc.path, fmt.Sprintf("%s-denied-%d", tc.key, i), bad, 403)
				if strings.Contains(out, `"data"`) || strings.Contains(out, "foreign-collector") || strings.Contains(out, collectorSecret) {
					t.Fatal("denied attribution exposed a result, claim or credential")
				}
				// Provenance preflight must precede even a completed replay's
				// fingerprint conflict or cached response.
				postJSON(t, s, collectorSecret, tc.path, tc.key, bad, 403)
			}
			postJSON(t, s, adminSecret, tc.path, "unbound-"+tc.key, tc.body, 403)
			if tc.path == "/v1/evidence" {
				bad := map[string]any{"type": "manual", "title": "Note", "payload_hash": evidence["payload_hash"], "collector_id": "foreign-collector"}
				postJSON(t, s, collectorSecret, tc.path, "top-level-conflict", bad, 403)
				postJSON(t, s, adminSecret, tc.path, "top-level-unbound", bad, 403)
			}
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before.Evidence, after.Evidence) || !reflect.DeepEqual(before.BuildRuns, after.BuildRuns) || !reflect.DeepEqual(before.AuditEntries, after.AuditEntries) || !reflect.DeepEqual(before.OutboxJobs, after.OutboxJobs) || !reflect.DeepEqual(before.ObjectPayloads, after.ObjectPayloads) || !reflect.DeepEqual(before.Idempotency, after.Idempotency) {
				t.Fatal("rejected attribution created evidence, audit, payload or replay effects", err)
			}
		})
	}
}
