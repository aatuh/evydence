package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestEvidencePointFixtureReadsRepositoryAndDiscardsFailedCommit(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("point query consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/evidence/" + owner.original.ID
	begins := factory.beginCalls
	body := getRaw(t, server, "fixture", path, http.StatusOK).Body.Bytes()
	var response struct {
		Data domain.EvidenceItem `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(owner.original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(response.Data)
	if err != nil || !bytes.Equal(got, want) || factory.beginCalls != begins+1 {
		t.Fatal("point fixture lost a current complete projection", string(got), string(want), err)
	}
	factory.fail = true
	begins, rollbacks := factory.beginCalls, factory.rollbacks
	body = getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.Bytes()
	if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
		t.Fatal("failed point commit retained its transaction")
	}
	for _, private := range []string{"private-query-commit-secret", `"data"`, `"canonical_hash"`, `"metadata"`} {
		if strings.Contains(string(body), private) {
			t.Fatal("failed point commit exposed private diagnostics or partial data", string(body))
		}
	}
	read := evidenceReadFixture{catalogFixtureCommands{ledger: rebound}}
	if point, err := read.GetEvidence(t.Context(), owner.actor, owner.original.ID); err == nil || point.ID != "" {
		t.Fatal("failed point commit returned a partial projection", point, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("point reads or failed commits changed current rows", err)
	}
	read.ledger = newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	if _, err := read.GetEvidence(t.Context(), owner.actor, owner.original.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository used an aggregate fallback", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := read.GetEvidence(ctx, owner.actor, owner.original.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("point fixture ignored cancellation", err)
	}
	explicit := &evidencePointQueryFake{}
	server.evidencePointQuery = explicit
	server.bindLegacyLedgerFixture(ledger)
	if server.evidencePointQuery != explicit {
		t.Fatal("rebinding replaced explicit evidence point port")
	}
}
