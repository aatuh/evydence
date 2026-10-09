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
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestControlFixtureReadsKeepOwnedCompletePagesAndDetachedDefinitions(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	second, err := ledger.CreateControlFramework(t.Context(), owner.actor, app.CreateControlFrameworkInput{Name: "Second", Version: "2", Description: "Second recorded framework"})
	if err != nil {
		t.Fatal(err)
	}
	var ownerLinks []domain.ControlEvidence
	for _, scope := range []controlFixtureScope{owner, foreign} {
		for _, subject := range []struct{ kind, id string }{{"evidence", scope.evidence.ID}, {"release", scope.release.ID}} {
			link, err := ledger.LinkControlEvidence(t.Context(), scope.actor, scope.control.ID, app.LinkControlEvidenceInput{EvidenceType: "build", SubjectType: subject.kind, SubjectID: subject.id, ProductID: scope.product.ID, ReleaseID: scope.release.ID, Confidence: "medium", Notes: "Recorded review"})
			if err != nil {
				t.Fatal(err)
			}
			if scope.actor.TenantID == owner.actor.TenantID {
				ownerLinks = append(ownerLinks, link)
			}
		}
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reader", Scopes: []string{"controls:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"controls:read"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"controls:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	packs, err := ledger.ListControlFrameworkTemplatePacks(t.Context(), human)
	if err != nil || len(packs) == 0 {
		t.Fatal("template catalog unavailable", err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want []any
	}{
		{"/v1/control-frameworks", []any{owner.framework, second}},
		{"/v1/control-evidence?control_id=" + owner.control.ID + "&product_id=" + owner.product.ID + "&release_id=" + owner.release.ID, []any{ownerLinks[0], ownerLinks[1]}},
		{"/v1/control-framework-template-packs", controlFixturePackValues(packs)},
	} {
		want := make(map[string]string, len(tc.want))
		for _, value := range tc.want {
			body, err := json.Marshal(value)
			var identity struct {
				ID string `json:"id"`
			}
			if err != nil || json.Unmarshal(body, &identity) != nil || identity.ID == "" {
				t.Fatal("invalid expected control DTO", err)
			}
			want[identity.ID] = string(body)
		}
		found := map[string]bool{}
		path, cursor := tc.path, ""
		baseSeparator := "?"
		if strings.Contains(tc.path, "?") {
			baseSeparator = "&"
		}
		for page := 0; page <= len(tc.want); page++ {
			separator := "?"
			if strings.Contains(path, "?") {
				separator = "&"
			}
			out := getRaw(t, server, "fixture-auth", path+separator+"page_size=1", 200)
			var result struct {
				Data []json.RawMessage `json:"data"`
				Meta struct {
					NextCursor string `json:"next_cursor"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil || len(result.Data) != 1 {
				t.Fatal("control page omitted a complete record", tc.path, err)
			}
			var identity struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(result.Data[0], &identity); err != nil || want[identity.ID] == "" || found[identity.ID] {
				t.Fatal("foreign or duplicate control page record", tc.path, err)
			}
			assertTrustHTTPReplay(t, want[identity.ID], string(result.Data[0]))
			found[identity.ID] = true
			if result.Meta.NextCursor == "" {
				break
			}
			if result.Meta.NextCursor == cursor {
				t.Fatal("control pagination failed to advance")
			}
			cursor = result.Meta.NextCursor
			path = tc.path + baseSeparator + "cursor=" + url.QueryEscape(cursor)
		}
		if len(found) != len(want) {
			t.Fatal("control pagination lost records", tc.path, found)
		}
	}
	point := "/v1/controls/" + owner.control.ID
	out := getRaw(t, server, "fixture-auth", point, 200)
	var control struct {
		Data domain.SecurityControl `json:"data"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &control); err != nil || !reflect.DeepEqual(control.Data, owner.control) {
		t.Fatal("security control DTO lost definition metadata", err)
	}
	getRaw(t, server, "fixture-auth", "/v1/controls/"+foreign.control.ID, 404)
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"controls:read"}}}} {
		auth.actor.ResourceGrants = grants
		getRaw(t, server, "fixture-auth", point, 403)
		getRaw(t, server, "fixture-auth", "/v1/control-frameworks", 403)
		controlFixtureAssertEmptyPage(t, server, "/v1/control-evidence")
	}
	// Starter packs contain no tenant data and intentionally require only the
	// credential scope, not a resource grant, in both old and focused readers.
	getRaw(t, server, "fixture-auth", "/v1/control-framework-template-packs", 200)
	auth.actor.Scopes = nil
	getRaw(t, server, "fixture-auth", "/v1/control-framework-template-packs", 403)
	auth.actor = human
	for _, filter := range []string{"control_id=" + foreign.control.ID, "product_id=" + foreign.product.ID, "release_id=" + foreign.release.ID} {
		controlFixtureAssertEmptyPage(t, server, "/v1/control-evidence?"+filter)
	}
	fixture := catalogFixtureCommands{ledger: ledger}
	reader, links := controlReadFixture{fixture}, controlEvidencePageFixture{fixture}
	definition, err := reader.GetSecurityControl(t.Context(), human, owner.control.ID)
	if err != nil {
		t.Fatal(err)
	}
	definition.EvidenceRequirements[0].Type = "modified"
	definition.Applicability[0], definition.Limitations[0] = "modified", "modified"
	projected, err := reader.ListTemplatePacks(t.Context(), human)
	if err != nil {
		t.Fatal(err)
	}
	for _, pack := range projected {
		for index := range pack.Controls {
			v := &pack.Controls[index]
			v.Title = "modified"
			if len(v.EvidenceRequirements) > 0 {
				v.EvidenceRequirements[0].Type = "modified"
			}
			if len(v.Applicability) > 0 {
				v.Applicability[0] = "modified"
			}
			if len(v.Limitations) > 0 {
				v.Limitations[0] = "modified"
			}
		}
	}
	again, err := ledger.GetSecurityControl(t.Context(), human, owner.control.ID)
	if err != nil || !reflect.DeepEqual(again, owner.control) {
		t.Fatal("control fixture exposed stored aliases", err)
	}
	againPacks, err := ledger.ListControlFrameworkTemplatePacks(t.Context(), human)
	if err != nil || !reflect.DeepEqual(againPacks, packs) {
		t.Fatal("template fixture exposed stored aliases", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	if _, err := reader.ListFrameworksPage(cancelled, human, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled frameworks accepted", err)
	}
	if _, err := reader.GetSecurityControl(cancelled, human, owner.control.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled control accepted", err)
	}
	if _, err := reader.ListTemplatePacks(cancelled, human); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled templates accepted", err)
	}
	if _, err := links.ListPage(cancelled, human, riskquery.ControlEvidenceFilter{}, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled control links accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("control reads or returned definition mutations changed state", err)
	}
}

func controlFixturePackValues(packs []domain.ControlFrameworkTemplatePack) []any {
	values := make([]any, 0, len(packs))
	for _, pack := range packs {
		values = append(values, pack)
	}
	return values
}

func controlFixtureAssertEmptyPage(t *testing.T, server *Server, path string) {
	t.Helper()
	out := getRaw(t, server, "fixture-auth", path, 200)
	var result struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil || len(result.Data) != 0 {
		t.Fatal("unowned or revoked control link inventory exposed", err)
	}
}
