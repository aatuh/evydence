package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func TestEvidencePageFixturesUseCurrentRepositoryAndDiscardFailedCommits(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("evidence page consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"/v1/evidence?type=manual&page_size=1&sort=id", "/v1/evidence/search?product_id=" + owner.product.ID + "&type=manual&source_system=api&page_size=1&sort=id"}
	for _, path := range paths {
		begins := factory.beginCalls
		body := getRaw(t, server, "fixture", path, http.StatusOK).Body.Bytes()
		var response struct {
			Data []domain.EvidenceItem `json:"data"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &response); err != nil || len(response.Data) != 1 || response.Meta.NextCursor == "" || factory.beginCalls != begins+1 {
			t.Fatal("repository-only page lost current rows or continuation", string(body), err)
		}
		want, err := json.Marshal(before.Evidence[response.Data[0].ID])
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(response.Data[0])
		if err != nil || string(got) != string(want) {
			t.Fatal("page lost complete public metadata", string(got), string(want), err)
		}
	}
	factory.fail = true
	for _, path := range paths {
		begins, rollbacks := factory.beginCalls, factory.rollbacks
		body := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
		if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
			t.Fatal("failed page commit retained transaction", path)
		}
		for _, private := range []string{"private-query-commit-secret", `"data"`, `"metadata"`, `"next_cursor"`} {
			if strings.Contains(body, private) {
				t.Fatal("failed page exposed private diagnostics or partial rows", body)
			}
		}
	}
	read := evidencePageFixture{catalogFixtureCommands{ledger: rebound}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	if result, err := read.ListPage(t.Context(), owner.actor, evidencequery.EvidencePageFilter{}, page, nil); err == nil || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("failed commit returned partial page", result, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("page reads or failed commits changed current rows", err)
	}
	read.ledger = newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	if _, err := read.ListPage(t.Context(), owner.actor, evidencequery.EvidencePageFilter{}, page, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing page repository used aggregate fallback", err)
	}
	explicit := &evidencePageHTTPStub{}
	server.evidencePageQuery = explicit
	server.bindLegacyLedgerFixture(ledger)
	if server.evidencePageQuery != explicit {
		t.Fatal("rebinding replaced explicit evidence page query")
	}
}
