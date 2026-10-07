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

type policyHTTPFake struct {
	calls, authorizations int
	err                   error
}

func (f *policyHTTPFake) AuthorizeCreateCustomPolicy(context.Context, identitydomain.Actor, riskapp.CreateCustomPolicyInput) error {
	f.authorizations++
	return f.err
}
func (f *policyHTTPFake) AuthorizeEvaluateCustomPolicy(context.Context, identitydomain.Actor, string, string) error {
	f.authorizations++
	return f.err
}
func (f *policyHTTPFake) CreateCustomPolicy(context.Context, identitydomain.Actor, riskapp.CreateCustomPolicyInput) (riskdomain.CustomPolicy, error) {
	f.calls++
	return riskdomain.CustomPolicy{ID: "policy"}, f.err
}
func (f *policyHTTPFake) EvaluateCustomPolicy(context.Context, identitydomain.Actor, string, string) (riskdomain.CustomPolicyEvaluation, error) {
	f.calls++
	return riskdomain.CustomPolicyEvaluation{ID: "evaluation"}, f.err
}
func TestCustomPolicyHTTPRejectsIncompleteCompositionAndSafeProblems(t *testing.T) {
	base, secret := testServer(t)
	f := &policyHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{CustomPolicyCommands: f}); err == nil {
		t.Fatal("policy commands silently use Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{CustomPolicyCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []struct{ path, body string }{{"/v1/custom-policies", `{"name":"Policy","version":"1","rules":[{"name":"rule","severity":"low"}]}`}, {"/v1/custom-policies/policy/evaluate", `{"release_id":"release"}`}} {
		postRaw(t, s, "", req.path, "unauth", []byte(req.body), 401)
		if executor.calls+f.calls+f.authorizations != 0 {
			t.Fatal("unauthenticated policy effects")
		}
	}
	for _, req := range []struct{ path, body string }{{"/v1/custom-policies", `{"name":"Policy","version":"1","rules":[{"name":"rule","severity":"low"}]}`}, {"/v1/custom-policies/policy/evaluate", `{"release_id":"release"}`}} {
		for i, problem := range []struct {
			err    error
			status int
		}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {fmt.Errorf("private SQL password"), 500}} {
			f.err = fmt.Errorf("policy boundary: %w", problem.err)
			body := postRaw(t, s, secret, req.path, fmt.Sprintf("problem-%d", i), []byte(req.body), problem.status)
			if strings.Contains(body, "private") || strings.Contains(body, "policy boundary") {
				t.Fatal("policy leaked internals", body)
			}
		}
	}
}
