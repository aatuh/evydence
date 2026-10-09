package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestSigningKeyNativeFixtureReadsCurrentRepositoryAndCommitFailureReturnsNothing(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	seedEvidenceFixtureScope(t, ledger, "Foreign")
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("public key query consulted aggregate clock") }})
	query := signingKeyFixtureQuery{catalogFixtureCommands{ledger: rebound}}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	page, err := query.ListPage(t.Context(), owner.actor, request, nil)
	if err != nil || len(page.Items) != 1 || page.Items[0].TenantID != owner.actor.TenantID || page.Next != nil || signingKeyFromQuery(page.Items[0]).Private != nil {
		t.Fatal("native key query used stale caches or exposed private/foreign data", err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("key query changed repository state", err)
	}
	factory.fail = true
	page, err = query.ListPage(t.Context(), owner.actor, request, nil)
	if err == nil || !reflect.DeepEqual(page, appquery.Result[verificationdomain.SigningKey]{}) {
		t.Fatal("failed read transaction exposed a public key page", err)
	}
}

func TestSigningKeyNativeFixtureRequiresRepositoryAndPreservesExplicitPort(t *testing.T) {
	reads := 0
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", Now: func() time.Time { reads++; return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }})
	query := signingKeyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	beforeClock := reads
	page, err := query.ListPage(t.Context(), actor, request, nil)
	if !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(page, appquery.Result[verificationdomain.SigningKey]{}) || reads != beforeClock {
		t.Fatal("missing repository fell back to aggregate or exposed data", err)
	}
	denied := actor
	denied.Scopes = nil
	if _, err := query.ListPage(t.Context(), denied, request, nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("missing authority reached repository composition", err)
	}
	var missingContext context.Context // Deliberate invalid-input characterization.
	if _, err := query.ListPage(missingContext, actor, request, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil context was accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.ListPage(ctx, actor, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated", err)
	}
	explicit := &signingKeyQueryFake{}
	server := &Server{signingKeyQuery: explicit}
	server.bindVerificationReadFixturePorts(ledger)
	if server.signingKeyQuery != explicit {
		t.Fatal("fixture binding replaced an explicit focused query")
	}
}
