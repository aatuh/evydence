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
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestVEXDocumentFixtureReadsCurrentRepositoryAndDiscardsFailedCommit(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("VEX document consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/vex/" + owner.vex.ID
	begins := factory.beginCalls
	body := getRaw(t, server, "fixture", path, http.StatusOK).Body.String()
	want, err := json.Marshal(map[string]any{"data": owner.vex, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertPackageReportFixtureResponse(t, path, string(want), body)
	if factory.beginCalls != begins+1 {
		t.Fatal("VEX document did not use exactly one repository view")
	}
	factory.fail = true
	begins, rollbacks := factory.beginCalls, factory.rollbacks
	body = getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
	if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
		t.Fatal("failed VEX read retained its transaction")
	}
	for _, private := range []string{"private-query-commit-secret", `"data"`, `"author"`, `"status_summary"`, "payload_ref"} {
		if strings.Contains(body, private) {
			t.Fatal("failed VEX read exposed diagnostics or partial metadata", body)
		}
	}
	read := evidenceReadFixture{catalogFixtureCommands{ledger: rebound}}
	if value, err := read.GetVEXDocument(t.Context(), owner.actor, owner.vex.ID); err == nil || !reflect.DeepEqual(value, evidencedomain.VEXDocument{}) {
		t.Fatal("failed VEX commit returned a partial document", value, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("VEX reads or failed commits changed recorded rows", err)
	}
	read.ledger = newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	if _, err := read.GetVEXDocument(t.Context(), owner.actor, owner.vex.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing VEX repository used an aggregate fallback", err)
	}
	query := &vexPointQueryFake{}
	server.vexPointQuery = query
	server.bindLegacyLedgerFixture(ledger)
	if server.vexPointQuery != query {
		t.Fatal("rebinding replaced the explicit VEX query")
	}
}
