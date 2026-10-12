package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var selfSessionCases = []Action{"sso_sessions.logout"}

func TestSelfSessionPolicyUsesAuthenticatedPrincipalWithoutGrantOrScope(t *testing.T) {
	request := Request{Action: "sso_sessions.logout"}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session"}
	for _, scopes := range [][]string{nil, {"unrelated"}, {"identity:logout"}, {"admin"}, {"*"}} {
		actor.Scopes = scopes
		actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}}}
		if err := Authorize(t.Context(), actor, request); err != nil {
			t.Fatal("owner cannot log out after grant/scope downgrade", scopes, err)
		}
	}
	for _, edit := range []func(*identitydomain.Actor){
		func(a *identitydomain.Actor) { a.KeyID = "key" }, func(a *identitydomain.Actor) { a.CollectorID = "collector" }, func(a *identitydomain.Actor) { a.SessionID = "" }, func(a *identitydomain.Actor) { a.SessionID = "  " }, func(a *identitydomain.Actor) { a.UserID = "  " },
	} {
		bad := actor
		edit(&bad)
		if err := Authorize(t.Context(), bad, request); !errors.Is(err, ErrForbidden) {
			t.Fatal("non-session or mixed credential authorized logout", err)
		}
	}
	for _, bad := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:logout", "*"}}, {TenantID: "tenant", CollectorID: "collector", Scopes: []string{"*"}}} {
		if err := Authorize(t.Context(), bad, request); !errors.Is(err, ErrForbidden) {
			t.Fatal("issued capability minted an owned session", err)
		}
	}
	for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation, Evaluation(255)} {
		if err := Authorize(t.Context(), actor, Request{Action: request.Action, Evaluation: mode}); !errors.Is(err, ErrForbidden) {
			t.Fatal("logout accepts policy phase promotion", mode, err)
		}
	}
	for i := 0; i < reflect.TypeOf(request.Resources).NumField(); i++ {
		bad := request
		reflect.ValueOf(&bad.Resources).Elem().Field(i).SetString("foreign")
		if err := Authorize(t.Context(), actor, bad); !errors.Is(err, ErrForbidden) {
			t.Fatal("logout accepts target coordinates", i, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Authorize(ctx, actor, request); !errors.Is(err, context.Canceled) {
		t.Fatal("logout canceled context", err)
	}
}
