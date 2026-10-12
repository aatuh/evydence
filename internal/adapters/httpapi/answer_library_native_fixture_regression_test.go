package httpapi

import (
	"context"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestAnswerLibraryFixtureReadsRepositoryRowsWithoutAggregatePublication(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedQuestionnaireFixtureScope(t, ledger, "Native")
	entry := owner.entry
	entry.ID = "repository-only-answer"
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Enterprise.InsertQuestionnaireAnswerLibraryEntry(ctx, entry)
	}); err != nil {
		t.Fatal(err)
	}
	reader := answerLibraryFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	actor := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"package:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"package:read"}}}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var cursor *appquery.SortKey
	for i := 0; i < 3; i++ {
		page, err := reader.ListPage(t.Context(), actor, packagequery.AnswerLibraryFilter{ProductID: owner.product.ID}, request, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range page.Items {
			if seen[v.ID] {
				t.Fatal("duplicate page entry", v.ID)
			}
			seen[v.ID] = true
			if v.ID == entry.ID && !reflect.DeepEqual(v, answerLibraryFixtureModel(entry)) {
				t.Fatal("repository answer lost fields", v)
			}
		}
		cursor = page.Next
		if cursor == nil {
			break
		}
	}
	if len(seen) != 2 || !seen[entry.ID] {
		t.Fatal("page reader consulted stale aggregate answer cache", seen)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native reads changed repository state", err)
	}
}
