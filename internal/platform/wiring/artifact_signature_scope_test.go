package wiring

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
)

func TestPostgresArtifactSignatureCreationScopeOmitsMutableDigest(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSubjectVerificationScopes(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest=repeat('x',1025),name=repeat('private-',1200000)WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
		guard, ok := repos.SupplyChain.(interface {
			LockArtifactSignatureCreationScope(context.Context, string, string) (application.ResourceReferences, error)
		})
		if !ok {
			t.Fatal("missing flat artifact creation scope locker")
		}
		refs, err := guard.LockArtifactSignatureCreationScope(ctx, "tenant", "artifact")
		if err != nil || refs != (application.ResourceReferences{ArtifactID: "artifact"}) {
			t.Fatal(refs, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if dsseHTTPCounts(t, p) != [5]int{} {
		t.Fatal("scope guard wrote effects")
	}
}
