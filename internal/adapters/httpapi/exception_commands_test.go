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

type exceptionHTTPFake struct {
	calls, authorizations int
	err                   error
}

func (f *exceptionHTTPFake) AuthorizeCreateException(context.Context, identitydomain.Actor, riskapp.CreateExceptionInput) error {
	f.authorizations++
	return f.err
}
func (f *exceptionHTTPFake) CreateException(context.Context, identitydomain.Actor, riskapp.CreateExceptionInput) (riskdomain.Exception, error) {
	f.calls++
	return riskdomain.Exception{ID: "exception"}, f.err
}
func (f *exceptionHTTPFake) AuthorizeApproveException(context.Context, identitydomain.Actor, string) error {
	f.authorizations++
	return f.err
}
func (f *exceptionHTTPFake) ApproveException(context.Context, identitydomain.Actor, string) (riskdomain.Exception, error) {
	f.calls++
	return riskdomain.Exception{ID: "exception", Approved: true}, f.err
}

func TestExceptionHTTPRejectsIncompleteCompositionAndUnauthenticatedTransactions(t *testing.T) {
	base, secret := testServer(t)
	f := &exceptionHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{ExceptionCommands: f}); err == nil {
		t.Fatal("exceptions silently fell back to Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{ExceptionCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	create := `{"release_id":"release","owner":"Owner","reason":"Reviewed","expires_at":"2030-01-01T00:00:00Z"}`
	postRaw(t, server, "", "/v1/exceptions", "unauth-create", []byte(create), 401)
	postRaw(t, server, "", "/v1/exceptions/exception/approve", "unauth-approve", []byte(`{}`), 401)
	if executor.calls+f.calls+f.authorizations != 0 {
		t.Fatal("unauthenticated request reached exception transaction")
	}
	for _, path := range []string{"/v1/exceptions", "/v1/exceptions/exception/approve"} {
		body := create
		if strings.HasSuffix(path, "approve") {
			body = `{}`
		}
		for i, test := range []struct {
			err    error
			status int
		}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {fmt.Errorf("private exception SQL"), 500}} {
			f.err = fmt.Errorf("exception boundary: %w", test.err)
			response := postRaw(t, server, secret, path, fmt.Sprintf("problem-%d", i), []byte(body), test.status)
			if strings.Contains(response, "private") || strings.Contains(response, "exception boundary") {
				t.Fatal("exception problem leaked internals", response)
			}
		}
	}
}
