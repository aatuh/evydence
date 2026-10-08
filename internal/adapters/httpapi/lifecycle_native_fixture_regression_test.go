package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

func TestLifecycleFixtureReadsCurrentRepositoryAndDiscardsFailedCommits(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("lifecycle query consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for id, event := range before.EvidenceLifecycle {
		if event.EvidenceID == owner.original.ID {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	want := before.EvidenceLifecycle[ids[0]]
	want.Details = map[string]any{"note": "visible", "nested": map[string]any{"value": "original"}}
	path := "/v1/evidence/" + owner.original.ID + "/lifecycle-events?sort=id&page_size=1"
	begins := factory.beginCalls
	body := getRaw(t, server, "fixture", path, http.StatusOK).Body.Bytes()
	var response struct {
		Data []domain.EvidenceLifecycleEvent `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &response); err != nil || !reflect.DeepEqual(response.Data, []domain.EvidenceLifecycleEvent{want}) || response.Meta.NextCursor == "" || factory.beginCalls != begins+1 {
		t.Fatal("lifecycle fixture lost a current redacted page", string(body), err)
	}
	if strings.Contains(string(body), "private-value") {
		t.Fatal("lifecycle fixture exposed private details")
	}
	factory.fail = true
	begins, rollbacks := factory.beginCalls, factory.rollbacks
	body = getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.Bytes()
	if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
		t.Fatal("failed lifecycle read retained its transaction")
	}
	for _, private := range []string{"private-query-commit-secret", `"data"`, `"details"`, `"next_cursor"`} {
		if strings.Contains(string(body), private) {
			t.Fatal("failed lifecycle commit exposed partial data or diagnostics", string(body))
		}
	}
	read := lifecyclePageFixture{catalogFixtureCommands{ledger: rebound}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := read.ListPage(t.Context(), owner.actor, owner.original.ID, page, nil)
	if err == nil || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("failed commit returned a partial lifecycle page", result, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("lifecycle reads or failed commits changed recorded rows", err)
	}
	read.ledger = newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	if _, err := read.ListPage(t.Context(), owner.actor, owner.original.ID, page, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing lifecycle repository used an aggregate fallback", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := read.ListPage(ctx, owner.actor, owner.original.ID, page, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("lifecycle query ignored cancellation", err)
	}
	explicit := &lifecycleEventsQueryFake{}
	server.lifecycleEventsQuery = explicit
	server.bindLegacyLedgerFixture(ledger)
	if server.lifecycleEventsQuery != explicit {
		t.Fatal("rebinding replaced an explicit lifecycle query")
	}
}
