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

type waiverHTTPFake struct {
	calls, authorizations int
	err                   error
}

func (f *waiverHTTPFake) AuthorizeCreateWaiver(context.Context, identitydomain.Actor, riskapp.CreateWaiverInput) error {
	f.authorizations++
	return f.err
}
func (f *waiverHTTPFake) CreateWaiver(context.Context, identitydomain.Actor, riskapp.CreateWaiverInput) (riskdomain.Waiver, error) {
	f.calls++
	return riskdomain.Waiver{ID: "waiver"}, f.err
}
func (f *waiverHTTPFake) AuthorizeApproveWaiver(context.Context, identitydomain.Actor, string) error {
	f.authorizations++
	return f.err
}
func (f *waiverHTTPFake) ApproveWaiver(context.Context, identitydomain.Actor, string) (riskdomain.Waiver, error) {
	f.calls++
	return riskdomain.Waiver{ID: "waiver", Approved: true}, f.err
}

func TestWaiverHTTPRejectsIncompleteCompositionAndUnauthenticatedTransactions(t *testing.T) {
	base, secret := testServer(t)
	f := &waiverHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{WaiverCommands: f}); err == nil {
		t.Fatal("waivers silently fell back to Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{WaiverCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	create := `{"scope_type":"release","scope_id":"release","owner":"Owner","risk":"low","reason":"Reviewed","expires_at":"2030-01-01T00:00:00Z"}`
	postRaw(t, server, "", "/v1/waivers", "unauth-create", []byte(create), 401)
	postRaw(t, server, "", "/v1/waivers/waiver/approve", "unauth-approve", []byte(`{}`), 401)
	if executor.calls+f.calls+f.authorizations != 0 {
		t.Fatal("unauthenticated request reached waiver transaction")
	}
	for _, path := range []string{"/v1/waivers", "/v1/waivers/waiver/approve"} {
		body := create
		if strings.HasSuffix(path, "approve") {
			body = `{}`
		}
		for i, test := range []struct {
			err    error
			status int
		}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {fmt.Errorf("private waiver SQL"), 500}} {
			f.err = fmt.Errorf("waiver boundary: %w", test.err)
			response := postRaw(t, server, secret, path, fmt.Sprintf("problem-%d", i), []byte(body), test.status)
			if strings.Contains(response, "private") || strings.Contains(response, "waiver boundary") {
				t.Fatal("waiver problem leaked internals", response)
			}
		}
	}
}
