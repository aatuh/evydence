package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestSigningFixtureReadsRepositoryProviderWithoutAggregatePublication(t *testing.T) {
	ledger, factory, objects, signer := reportSigningRegressionLedger(t)
	owner := seedReportSigningFixtureScope(t, ledger, "Native")
	p := owner.provider
	p.ID = "repository-only-provider"
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Integrity.InsertSigningProvider(ctx, p)
	}); err != nil {
		t.Fatal(err)
	}
	f := reportSigningFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, signer: signer}
	v, err := f.CreateSigningOperation(t.Context(), owner.actor, verificationapp.SigningOperationInput{ProviderID: p.ID, SubjectType: "release", SubjectID: owner.release.ID, PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil || v.ProviderID != p.ID || v.SignatureRef == "" || signer.calls != 1 {
		t.Fatal("signing consulted stale provider cache", v, err)
	}
	saved, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Signatures[v.SignatureRef].KeyID != p.ID || saved.SigningOperations[v.ID].ProviderID != p.ID {
		t.Fatal("signature/operation lost persisted provider binding")
	}
}
