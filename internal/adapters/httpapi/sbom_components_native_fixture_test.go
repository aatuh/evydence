package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func TestSBOMComponentFixtureTraversesMoreThanLegacyInventoryCap(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	components := make([]map[string]string, 501)
	for i := range components {
		components[i] = map[string]string{"type": "library", "name": fmt.Sprintf("lib-%03d", i), "purl": fmt.Sprintf("pkg:generic/lib-%03d@1", i)}
	}
	payload, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ledger.UploadSBOM(t.Context(), owner.actor, owner.release.ID, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data []domain.SBOMComponentRecord `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	path := "/v1/sbom-components?sbom_id=" + url.QueryEscape(b.ID) + "&limit=500"
	server.authn = &configuredAuthenticator{actor: owner.actor}
	first := getRaw(t, server, "fixture", path, http.StatusOK)
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 500 || response.Meta.NextCursor == "" {
		t.Fatal("first component page lost continuation beyond 500 records", len(response.Data), response.Meta.NextCursor, err)
	}
	seen := map[string]bool{}
	want := map[string]domain.SBOMComponentRecord{}
	for i, component := range b.Components {
		id := fmt.Sprintf("%s:%d", b.ID, i)
		want[id] = domain.SBOMComponentRecord{ID: id, SBOMID: b.ID, ReleaseID: b.ReleaseID, ArtifactID: b.ArtifactID, Format: b.Format, SpecVersion: b.SpecVersion, Component: component}
	}
	for _, item := range response.Data {
		if seen[item.ID] || !reflect.DeepEqual(item, want[item.ID]) {
			t.Fatal("component page repeated or lost public metadata", item)
		}
		seen[item.ID] = true
	}
	second := getRaw(t, server, "fixture", path+"&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	response.Data, response.Meta.NextCursor = nil, ""
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Meta.NextCursor != "" || seen[response.Data[0].ID] {
		t.Fatal("component continuation omitted or repeated a record", response, err)
	}
	if !reflect.DeepEqual(response.Data[0], want[response.Data[0].ID]) {
		t.Fatal("component continuation lost public metadata", response.Data[0])
	}
	seen[response.Data[0].ID] = true
	if len(seen) != 501 {
		t.Fatal("component inventory was silently truncated", len(seen))
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("component HTTP pages changed stored state", err)
	}
}

func TestSBOMComponentFixtureUsesCurrentRepositoryAndDiscardsFailedCommits(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("component query consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/sbom-components?sbom_id=" + url.QueryEscape(owner.sbom.ID) + "&limit=1"
	begins := factory.beginCalls
	body := getRaw(t, server, "fixture", path, http.StatusOK).Body.String()
	if factory.beginCalls != begins+1 || !strings.Contains(body, `"name":"one"`) || !strings.Contains(body, `"next_cursor"`) {
		t.Fatal("component fixture did not use one current repository view", body)
	}
	factory.fail = true
	begins, rollbacks := factory.beginCalls, factory.rollbacks
	body = getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
	if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
		t.Fatal("failed component read retained its transaction")
	}
	for _, private := range []string{"private-query-commit-secret", `"data"`, `"component"`, `"next_cursor"`} {
		if strings.Contains(body, private) {
			t.Fatal("failed component commit exposed diagnostics or partial page", body)
		}
	}
	read := sbomComponentsFixture{catalogFixtureCommands{ledger: rebound}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := read.ListPage(t.Context(), owner.actor, evidencequery.SBOMComponentFilter{SBOMID: owner.sbom.ID}, page, nil)
	if err == nil || !reflect.DeepEqual(result, appquery.Result[evidencedomain.SBOMComponentRecord]{}) {
		t.Fatal("failed commit returned a partial component page", result, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("component reads or failed commits changed recorded rows", err)
	}
	read.ledger = newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	if _, err := read.ListPage(t.Context(), owner.actor, evidencequery.SBOMComponentFilter{}, page, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing component repository used an aggregate fallback", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := read.ListPage(ctx, owner.actor, evidencequery.SBOMComponentFilter{}, page, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("component query ignored cancellation", err)
	}
	explicit := &sbomComponentsQueryFake{}
	server.sbomComponentsQuery = explicit
	server.bindLegacyLedgerFixture(ledger)
	if server.sbomComponentsQuery != explicit {
		t.Fatal("rebinding replaced an explicitly configured component query")
	}
}
