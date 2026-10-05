package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type releaseStateHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	actor    identitydomain.Actor
	id       string
	revision int64
	err      error
}

func (f *releaseStateHTTPFake) AuthorizeReleaseTransition(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}

func (f *releaseStateHTTPFake) FreezeRelease(_ context.Context, actor identitydomain.Actor, id string, revision int64) (releasedomain.Release, error) {
	f.calls++
	f.actor, f.id, f.revision = actor, id, revision
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v, _ := releasedomain.NewRelease(id, actor.TenantID, "uncached-product", "1.0.0", at)
	v, _ = v.Freeze(at.Add(time.Minute))
	return v, f.err
}

func (f *releaseStateHTTPFake) ApproveRelease(ctx context.Context, actor identitydomain.Actor, id string, revision int64) (releasedomain.Release, error) {
	v, err := f.FreezeRelease(ctx, actor, id, revision)
	if err != nil {
		return v, err
	}
	v, err = v.Approve(v.CreatedAt.Add(2 * time.Minute))
	return v, err
}

func TestReleaseStateHTTPMapsFocusedTransitionsReplayRevisionAndErrors(t *testing.T) {
	local, secret := testServer(t)
	commands := &releaseStateHTTPFake{}
	server, err := NewServerWithOptions(local.ledger, ServerOptions{ReleaseStateCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	freezePath := "/v1/releases/uncached-release/freeze"
	response := postJSONWithIfMatch(t, server, secret, freezePath, "focused-freeze", 1, map[string]any{}, 200)
	if commands.calls != 1 || commands.actor.TenantID == "" || commands.id != "uncached-release" || commands.revision != 1 {
		t.Fatal("focused transition input changed", commands)
	}
	for _, field := range []string{`"id":"uncached-release"`, `"tenant_id":"` + commands.actor.TenantID + `"`, `"product_id":"uncached-product"`, `"version":"1.0.0"`, `"state":"frozen"`, `"revision":2`, `"created_at":"2026-01-02T03:04:05Z"`, `"frozen_at":"2026-01-02T03:05:05Z"`} {
		if !strings.Contains(response, field) {
			t.Fatal("transition DTO lost field", field, response)
		}
	}
	if strings.Contains(response, `"approved_at"`) {
		t.Fatal("freeze unexpectedly approved", response)
	}
	assertTrustHTTPReplay(t, response, postJSONWithIfMatch(t, server, secret, freezePath, "focused-freeze", 1, map[string]any{}, 200))
	if commands.calls != 1 {
		t.Fatal("transition replay executed twice", commands.calls)
	}
	postJSONWithIfMatch(t, server, secret, freezePath, "focused-freeze", 2, map[string]any{}, 409)
	approved := postJSONWithIfMatch(t, server, secret, "/v1/releases/uncached-release/approve", "focused-approve", 2, map[string]any{}, 200)
	if commands.revision != 2 || commands.calls != 2 || !strings.Contains(approved, `"state":"approved"`) || !strings.Contains(approved, `"revision":3`) || !strings.Contains(approved, `"approved_at":"2026-01-02T03:06:05Z"`) {
		t.Fatal("focused approval mapping changed", approved, commands)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.NewVersionConflict(2), 409}, {releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private transition SQL"), 500}} {
		commands.err = tc.err
		failure := postJSONWithIfMatch(t, server, secret, freezePath, fmt.Sprintf("transition-failure-%d", i), 1, map[string]any{}, tc.status)
		if strings.Contains(failure, "private transition SQL") || strings.Contains(failure, "uncached-product") {
			t.Fatal("transition failure leaked private state", failure)
		}
		if i == 0 && (!strings.Contains(failure, `"code":"VERSION_CONFLICT"`) || !strings.Contains(failure, `"current_revision":2`)) {
			t.Fatal("typed revision conflict lost", failure)
		}
		if i != 0 && strings.Contains(failure, `"current_revision"`) {
			t.Fatal("unauthorized or unrelated error exposed revision", failure)
		}
	}
}
