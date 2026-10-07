package httpapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sbomDiffHTTPFake struct {
	calls, authorizations int
	err                   error
}

func (f *sbomDiffHTTPFake) AuthorizeCreateSBOMDiff(context.Context, identitydomain.Actor, evidenceapp.CreateSBOMDiffInput) error {
	f.authorizations++
	return f.err
}
func (f *sbomDiffHTTPFake) CreateSBOMDiff(context.Context, identitydomain.Actor, evidenceapp.CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error) {
	f.calls++
	return evidencedomain.SBOMDiff{ID: "diff"}, f.err
}
func TestSBOMDiffHTTPRequiresDurableExecutorAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &sbomDiffHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SBOMDiffCommands: f}); err == nil {
		t.Fatal("SBOM diff fell back to Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SBOMDiffCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"base_sbom_id":"base","target_sbom_id":"target"}`)
	postRaw(t, s, "", "/v1/sbom-diffs", "unauth", body, 401)
	if executor.calls+f.calls+f.authorizations != 0 {
		t.Fatal("unauthenticated effects")
	}
	for i, test := range []struct {
		err    error
		status int
	}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {fmt.Errorf("private SQL"), 500}} {
		f.err = fmt.Errorf("SBOM diff boundary: %w", test.err)
		b := postRaw(t, s, secret, "/v1/sbom-diffs", fmt.Sprintf("err-%d", i), body, test.status)
		if strings.Contains(b, "private") || strings.Contains(b, "boundary") {
			t.Fatal("internal error leaked", b)
		}
	}
}
