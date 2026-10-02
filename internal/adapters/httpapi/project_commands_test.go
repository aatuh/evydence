package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type projectHTTPFake struct {
	calls int
	actor identitydomain.Actor
	input releaseapp.CreateProjectInput
	err   error
}

func (f *projectHTTPFake) CreateProject(_ context.Context, actor identitydomain.Actor, in releaseapp.CreateProjectInput) (releasedomain.Project, error) {
	f.calls++
	f.actor, f.input = actor, in
	return releasedomain.Project{ID: "durable-project", TenantID: actor.TenantID, ProductID: in.ProductID, Name: in.Name, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, f.err
}

func TestProjectHTTPMapsFocusedDTOReplayAndPrivateErrors(t *testing.T) {
	local, secret := testServer(t)
	commands := &projectHTTPFake{}
	server, err := NewServerWithOptions(local.ledger, ServerOptions{ProjectCommands: commands})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"product_id":"uncached-product","name":"Project"}`)
	response := postRaw(t, server, secret, "/v1/projects", "create-project", body, 201)
	if commands.calls != 1 || commands.actor.TenantID == "" || !reflect.DeepEqual(commands.input, releaseapp.CreateProjectInput{ProductID: "uncached-product", Name: "Project"}) {
		t.Fatal("focused project input changed", commands)
	}
	for _, field := range []string{`"id":"durable-project"`, `"tenant_id":"` + commands.actor.TenantID + `"`, `"product_id":"uncached-product"`, `"name":"Project"`, `"created_at":"2026-01-02T03:04:05Z"`} {
		if !strings.Contains(response, field) {
			t.Fatal("project response lost field", field, response)
		}
	}
	if replay := postRaw(t, server, secret, "/v1/projects", "create-project", body, 201); replay != response || commands.calls != 1 {
		t.Fatal("project replay changed result or repeated command", replay, commands.calls)
	}
	postRaw(t, server, secret, "/v1/projects", "create-project", append(body, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private project SQL"), 500}} {
		commands.err = tc.err
		failure := postRaw(t, server, secret, "/v1/projects", fmt.Sprintf("project-failure-%d", i), body, tc.status)
		if strings.Contains(failure, "private project SQL") || strings.Contains(failure, "durable-project") {
			t.Fatal("project error leaked internal detail or result", failure)
		}
	}
}
