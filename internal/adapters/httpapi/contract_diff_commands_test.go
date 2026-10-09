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

type contractDiffHTTPFake struct {
	calls, authorizations int
	err                   error
}

func (f *contractDiffHTTPFake) AuthorizeCreateContractDiff(context.Context, identitydomain.Actor, evidenceapp.CreateContractDiffInput) error {
	f.authorizations++
	return f.err
}
func (f *contractDiffHTTPFake) CreateContractDiff(context.Context, identitydomain.Actor, evidenceapp.CreateContractDiffInput) (evidencedomain.ContractDiff, error) {
	f.calls++
	return evidencedomain.ContractDiff{ID: "diff"}, f.err
}
func TestContractDiffHTTPRequiresDurableExecutorAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &contractDiffHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{ContractDiffCommands: f}); err == nil {
		t.Fatal("contract diff fell back to Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{ContractDiffCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"base_contract_id":"base","target_contract_id":"target"}`)
	postRaw(t, s, "", "/v1/openapi-diffs", "unauth", body, 401)
	if executor.calls+f.calls+f.authorizations != 0 {
		t.Fatal("unauthenticated effects")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {fmt.Errorf("private SQL"), 500}} {
		f.err = fmt.Errorf("contract diff boundary: %w", tc.err)
		b := postRaw(t, s, secret, "/v1/openapi-diffs", fmt.Sprintf("err-%d", i), body, tc.status)
		if strings.Contains(b, "private") || strings.Contains(b, "boundary") {
			t.Fatal("internal error leaked", b)
		}
	}
}
