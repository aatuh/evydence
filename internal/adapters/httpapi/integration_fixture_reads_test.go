package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

func TestIntegrationFixtureReadsKeepTenantScopeCompletePagesAndDetachedMetadata(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	second, _, oneTime, err := ledger.CreateCollector(t.Context(), owner.actor, app.CreateCollectorInput{Name: "Second", Type: "generic_ci", Version: "2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Authenticate(t.Context(), oneTime); err != nil {
		t.Fatal(err)
	}
	repository, err := ledger.CreateSourceRepository(t.Context(), owner.actor, app.CreateRepositoryInput{ProjectID: owner.project.ID, Provider: "gitlab", FullName: "fixture/second"})
	if err != nil {
		t.Fatal(err)
	}
	definition, err := ledger.CreateCommercialCollectorDefinition(t.Context(), owner.actor, app.CreateCommercialCollectorInput{Name: "Scanner", Provider: "fixture", Version: "1", ManifestHash: "sha256:" + strings.Repeat("a", 64), AllowedScopes: []string{"evidence:write"}})
	if err != nil {
		t.Fatal(err)
	}
	definition2, err := ledger.CreateCommercialCollectorDefinition(t.Context(), owner.actor, app.CreateCommercialCollectorInput{Name: "Second", Provider: "fixture", Version: "2", ManifestHash: "sha256:" + strings.Repeat("b", 64), AllowedScopes: []string{"evidence:write"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ledger.CreateCommercialCollectorDefinition(t.Context(), foreign.actor, app.CreateCommercialCollectorInput{Name: "Foreign", Provider: "fixture", Version: "1", ManifestHash: "sha256:" + strings.Repeat("c", 64), AllowedScopes: []string{"evidence:write"}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:read", "source:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"collector:read"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"source:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		ids  []string
	}{
		{"/v1/collectors", []string{owner.collector.ID, second.ID}},
		{"/v1/commercial-collectors", []string{definition.ID, definition2.ID}},
		{"/v1/source/repositories?project_id=" + owner.project.ID, []string{owner.repository.ID, repository.ID}},
	} {
		found := map[string]bool{}
		path := tc.path
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		for page := 0; page < 3; page++ {
			out := getRaw(t, server, "fixture-auth", path+separator+"page_size=1", 200)
			var result struct {
				Data []struct {
					ID       string `json:"id"`
					TenantID string `json:"tenant_id"`
				} `json:"data"`
				Meta struct {
					NextCursor string `json:"next_cursor"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil || len(result.Data) != 1 || result.Data[0].TenantID != owner.actor.TenantID || found[result.Data[0].ID] || strings.Contains(out.Body.String(), oneTime) || strings.Contains(out.Body.String(), `"hash"`) {
				t.Fatal("unscoped, duplicate or private integration page", err)
			}
			found[result.Data[0].ID] = true
			if result.Meta.NextCursor == "" {
				break
			}
			path = tc.path + separator + "cursor=" + url.QueryEscape(result.Meta.NextCursor)
			separator = "&"
		}
		if len(found) != len(tc.ids) {
			t.Fatal("fixture pagination lost records", tc.path, found)
		}
		for _, id := range tc.ids {
			if !found[id] {
				t.Fatal("fixture page omitted owned record", id)
			}
		}
	}
	getRaw(t, server, "fixture-auth", "/v1/collectors/"+foreign.collector.ID+"/health", 404)
	getRaw(t, server, "fixture-auth", "/v1/collectors/"+owner.collector.ID+"/health", 200)
	auth.actor.ResourceGrants = nil
	getRaw(t, server, "fixture-auth", "/v1/collectors", 403)
	getRaw(t, server, "fixture-auth", "/v1/commercial-collectors", 403)
	getRaw(t, server, "fixture-auth", "/v1/collectors/"+owner.collector.ID+"/health", 403)
	empty := getRaw(t, server, "fixture-auth", "/v1/source/repositories", 200)
	var page struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(empty.Body.Bytes(), &page); err != nil || len(page.Data) != 0 {
		t.Fatal("revoked source grants exposed inventory", err)
	}
	fixture := catalogFixtureCommands{ledger: ledger}
	request := appquery.PageRequest{PageSize: 10, Sort: appquery.SortID, Direction: appquery.Ascending}
	collectors, err := (collectorPageFixture{fixture}).ListPage(t.Context(), human, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := range collectors.Items {
		collectors.Items[index].AllowedScopes[0] = "modified"
		if seen := collectors.Items[index].LastSeenAt; seen != nil {
			*seen = seen.AddDate(1, 0, 0)
		}
	}
	report, err := (collectorHealthFixture{fixture}).Report(t.Context(), human, owner.collector.ID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := ledger.CollectorHealthReport(t.Context(), human, owner.collector.ID)
	if err != nil || !reflect.DeepEqual(collectorHealthFromQuery(report), original) {
		t.Fatal("health mapper lost public fields", err)
	}
	report.LatestRelease.Limitations[0] = "modified"
	report.Checks[0].Detail = "modified"
	definitions, err := (commercialCollectorPageFixture{fixture}).ListPage(t.Context(), human, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	definitions.Items[0].AllowedScopes[0] = "modified"
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (collectorPageFixture{fixture}).ListPage(cancelled, human, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled collector read accepted", err)
	}
	if _, err := (sourceRepositoryPageFixture{fixture}).ListPage(cancelled, human, owner.project.ID, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled source read accepted", err)
	}
	if _, err := (collectorHealthFixture{fixture}).Report(cancelled, human, owner.collector.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled health read accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read or detached metadata mutation changed integration state", err)
	}
	again, err := ledger.ListCollectors(t.Context(), owner.actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range again {
		if value.AllowedScopes[0] == "modified" {
			t.Fatal("collector scopes alias aggregate state")
		}
		if value.ID == second.ID && (value.LastSeenAt == nil || value.LastSeenAt.Year() != 2026) {
			t.Fatal("collector heartbeat timestamp aliased")
		}
	}
}
