package httpapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestVEXPreviewFixtureUsesCurrentRepositoryWithoutPublishingEffects(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("preview consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ path, payload string }{
		{"/v1/vex/preview", string(owner.payload)},
		{"/v1/vex/cyclonedx/preview", `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-1","analysis":{"state":"resolved"},"affects":[{"ref":"pkg:generic/one@1"}]}]}`},
	} {
		body, err := json.Marshal(map[string]any{"release_id": owner.release.ID, "payload": json.RawMessage(input.payload)})
		if err != nil {
			t.Fatal(err)
		}
		begins := factory.beginCalls
		response := postRaw(t, server, "fixture", input.path, "", body, http.StatusOK)
		if factory.beginCalls != begins+1 || !strings.Contains(response, `"advisory":true`) || !strings.Contains(response, `"decisions_would_create":1`) || strings.Contains(response, "payload_ref") {
			t.Fatal("preview lost current mapping or disclosed payload storage", response)
		}
		factory.fail = true
		response = postRaw(t, server, "fixture", input.path, "", body, http.StatusInternalServerError)
		for _, private := range []string{"private-query-commit-secret", `"data"`, `"status_summary"`, `"mapping_failures"`} {
			if strings.Contains(response, private) {
				t.Fatal("failed preview commit returned private diagnostics or partial data", response)
			}
		}
		factory.fail = false
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("preview published decisions, audit or outbox state", err)
	}
}
