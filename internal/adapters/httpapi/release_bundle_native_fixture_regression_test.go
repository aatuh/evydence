package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestReleaseBundleNativeFixtureReadsCurrentRowsAndDiscardsFailedCommit(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedPackageReportFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("bundle query consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		suffix string
		want   any
	}{{"", owner.bundle}, {"/manifest", owner.bundle.Manifest}} {
		begins := factory.beginCalls
		response := getRaw(t, server, "fixture", "/v1/release-bundles/"+owner.bundle.ID+request.suffix, http.StatusOK)
		want, err := json.Marshal(map[string]any{"data": request.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertPackageReportFixtureResponse(t, request.suffix, string(want), response.Body.String())
		if factory.beginCalls != begins+1 {
			t.Fatal("release-bundle point did not use exactly one repository transaction")
		}
	}
	factory.fail = true
	for _, suffix := range []string{"", "/manifest"} {
		begins, rollbacks := factory.beginCalls, factory.rollbacks
		body := getRaw(t, server, "fixture", "/v1/release-bundles/"+owner.bundle.ID+suffix, http.StatusInternalServerError).Body.String()
		if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
			t.Fatal("failed release-bundle read retained a transaction or retried a partial read")
		}
		for _, private := range []string{"private-query-commit-secret", owner.bundle.ManifestHash, `"data"`, `"signature_refs"`} {
			if strings.Contains(body, private) {
				t.Fatal("failed bundle commit exposed private errors or partial data", body)
			}
		}
	}
	if value, err := server.releaseBundleQuery.GetReleaseBundle(t.Context(), owner.actor, owner.bundle.ID); err == nil || !reflect.DeepEqual(value, packagedomain.ReleaseBundle{}) {
		t.Fatal("failed commit returned a partially populated release bundle", value, err)
	}
	reader := server.releaseBundleQuery.(packageBundleReadFixture)
	if value, err := reader.GetReleaseBundlePoint(t.Context(), owner.actor.TenantID, owner.bundle.ID); err == nil || !reflect.DeepEqual(value, packagequery.ReleaseBundlePoint{}) {
		t.Fatal("failed reader commit returned a partially populated bundle point", value, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("bundle reads or failed commits changed current repository rows", err)
	}
	missing := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	server.bindLegacyLedgerFixture(missing)
	if value, err := server.releaseBundleQuery.GetReleaseBundle(t.Context(), owner.actor, owner.bundle.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(value, packagedomain.ReleaseBundle{}) {
		t.Fatal("missing bundle repository fell back to aggregate state", value, err)
	}
	var absent context.Context
	if _, err := server.releaseBundleQuery.GetReleaseBundle(absent, owner.actor, owner.bundle.ID); !errors.Is(err, packagequery.ErrValidation) {
		t.Fatal("nil bundle-query context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := server.releaseBundleQuery.GetReleaseBundle(ctx, owner.actor, owner.bundle.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("bundle read ignored cancellation", err)
	}
	explicit := &releaseBundleQueryFake{}
	server.releaseBundleQuery = explicit
	server.bindLegacyLedgerFixture(rebound)
	if server.releaseBundleQuery != explicit {
		t.Fatal("rebinding replaced the explicitly configured bundle query")
	}
}
