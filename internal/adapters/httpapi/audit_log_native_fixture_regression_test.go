package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestAuditLogNativeFixtureReadsCurrentRowsPastInventoryCapAndCommitFailureReturnsNothing(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	seedEvidenceFixtureScope(t, ledger, "Foreign")
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, r app.Repositories) error {
		for i := range 501 {
			_, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: fmt.Sprintf("page-%03d", i), TenantID: owner.actor.TenantID, EntryType: "fixture.created", SubjectType: "native-page", SubjectID: "scope", ActorType: "api_key", ActorID: owner.actor.KeyID, OccurredAt: at, SchemaVersion: domain.AuditChainEntrySchemaVersion})
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("audit page consulted aggregate clock") }})
	query := auditLogFixtureQuery{catalogFixtureCommands{ledger: rebound}}
	filter := verificationquery.AuditFilter{SubjectType: "native-page", SubjectID: "scope", Since: &at}
	request := appquery.PageRequest{PageSize: 500, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	page, err := query.ListPage(t.Context(), owner.actor, filter, request, nil)
	if err != nil || len(page.Items) != 500 || page.Items[0].ID != "page-000" || page.Next == nil || page.Next.ID != "page-499" {
		t.Fatal("native audit query used caches, filtered incorrectly or retained inventory cap", err)
	}
	page, err = query.ListPage(t.Context(), owner.actor, filter, request, page.Next)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "page-500" || page.Next != nil {
		t.Fatal("native audit query omitted the record beyond 500", err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("audit pages changed immutable repository state", err)
	}
	factory.fail = true
	page, err = query.ListPage(t.Context(), owner.actor, filter, request, nil)
	if err == nil || !reflect.DeepEqual(page, appquery.Result[verificationdomain.AuditChainEntry]{}) {
		t.Fatal("failed read commit exposed a partial audit page", err)
	}
}

func TestAuditLogNativeFixtureRequiresRepositoryAndPreservesExplicitPort(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", Now: func() time.Time { panic("audit query used aggregate clock") }})
	query := auditLogFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	page, err := query.ListPage(t.Context(), actor, verificationquery.AuditFilter{}, request, nil)
	if !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(page, appquery.Result[verificationdomain.AuditChainEntry]{}) {
		t.Fatal("missing repository restored aggregate behavior or exposed a page", err)
	}
	actor.Scopes = nil
	if _, err := query.ListPage(t.Context(), actor, verificationquery.AuditFilter{}, request, nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("missing admin authority reached repository composition", err)
	}
	actor.Scopes = []string{"admin"}
	var missingContext context.Context
	if _, err := query.ListPage(missingContext, actor, verificationquery.AuditFilter{}, request, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil context was accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.ListPage(ctx, actor, verificationquery.AuditFilter{}, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated", err)
	}
	explicit := &auditLogQueryFake{}
	server := &Server{auditLogQuery: explicit}
	server.bindVerificationReadFixturePorts(ledger)
	if server.auditLogQuery != explicit {
		t.Fatal("fixture rebinding replaced an explicit native audit query")
	}
}
