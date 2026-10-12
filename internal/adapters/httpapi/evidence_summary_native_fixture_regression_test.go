package httpapi

import (
	"context"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestEvidenceSummaryFixtureReadsRepositoryMetadataWithoutAggregatePublication(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedQuestionnaireFixtureScope(t, ledger, "NativeSummary")
	e := owner.evidence
	e.ID = "repository-only-evidence"
	e.Title = "Current repository title"
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertEvidence(ctx, e)
	}); err != nil {
		t.Fatal(err)
	}
	f := summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	v, err := f.CreateEvidenceSummary(t.Context(), owner.actor, packageapp.CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: owner.release.ID, EvidenceIDs: []string{e.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Citations) != 1 || v.Citations[0].Title != e.Title {
		t.Fatal("summary consulted stale aggregate evidence metadata", v.Citations)
	}
	saved, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(summaryFixtureModel(saved.EvidenceSummaries[v.ID]), v) {
		t.Fatal("native summary lost complete persisted fields", err)
	}
}
