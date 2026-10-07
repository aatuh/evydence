package httpapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type policyEvaluationHTTPFake struct {
	calls, authorizations int
	err                   error
}

func (f *policyEvaluationHTTPFake) AuthorizeEvaluateRelease(context.Context, identitydomain.Actor, string) error {
	f.authorizations++
	return f.err
}
func (f *policyEvaluationHTTPFake) EvaluateRelease(context.Context, identitydomain.Actor, string) (riskdomain.PolicyEvaluation, error) {
	f.calls++
	return riskdomain.PolicyEvaluation{ID: "evaluation"}, f.err
}
func TestPolicyEvaluationHTTPRequiresDurableExecutorAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &policyEvaluationHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{PolicyEvaluationCommands: f}); err == nil {
		t.Fatal("policy evaluation fell back to Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{PolicyEvaluationCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	path, body := "/v1/policies/evaluate", []byte(`{"release_id":"release"}`)
	postRaw(t, s, "", path, "unauth", body, 401)
	if executor.calls+f.calls+f.authorizations != 0 {
		t.Fatal("unauthenticated policy effects")
	}
	for i, test := range []struct {
		err    error
		status int
	}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {fmt.Errorf("private SQL"), 500}} {
		f.err = fmt.Errorf("policy evaluation boundary: %w", test.err)
		b := postRaw(t, s, secret, path, fmt.Sprintf("error-%d", i), body, test.status)
		if strings.Contains(b, "private") || strings.Contains(b, "boundary") {
			t.Fatal("SQL/internal error leaked", b)
		}
	}
}
