package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestDecisionHistoryFixtureReadsReboundRepositoryAndFailsClosed(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }})
	owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("history consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/vulnerability-decisions?release_id=" + owner.release.ID + "&page_size=1"
	seen, cursor := map[string]bool{}, ""
	for i := 0; i < 3; i++ {
		begins := factory.beginCalls
		requestPath := path
		if cursor != "" {
			requestPath += "&cursor=" + url.QueryEscape(cursor)
		}
		response := getRaw(t, server, "fixture", requestPath, http.StatusOK)
		var envelope struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || len(envelope.Data) != 1 || factory.beginCalls != begins+1 || strings.Contains(response.Body.String(), "private triage") || seen[envelope.Data[0].ID] {
			t.Fatal("history lost current paging or disclosed private notes", response.Body.String(), err)
		}
		seen[envelope.Data[0].ID], cursor = true, envelope.Meta.NextCursor
		if (i == 2) != (cursor == "") {
			t.Fatal("history continuation ended early or repeated rows")
		}
	}
	if !seen[owner.head.ID] {
		t.Fatal("history omitted its active visible decision")
	}
	factory.fail = true
	response := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
	for _, private := range []string{"private-query-commit-secret", "private triage", owner.head.ID, `"data"`, `"next_cursor"`} {
		if strings.Contains(response, private) {
			t.Fatal("failed history commit returned partial data or diagnostics", response)
		}
	}
	factory.fail = false
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("history query changed repository data", err)
	}
}
