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

type releaseCreationHTTPFake struct {
	guards   int
	guardErr error
	calls    int
	actor    identitydomain.Actor
	input    releaseapp.CreateReleaseInput
	err      error
}

func (f *releaseCreationHTTPFake) AuthorizeReleaseCreation(context.Context, identitydomain.Actor, releaseapp.CreateReleaseInput) error {
	f.guards++
	return f.guardErr
}

func (f *releaseCreationHTTPFake) CreateRelease(_ context.Context, actor identitydomain.Actor, in releaseapp.CreateReleaseInput) (releasedomain.Release, error) {
	f.calls++
	f.actor, f.input = actor, in
	v, err := releasedomain.NewRelease("durable-release", actor.TenantID, in.ProductID, in.Version, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		return releasedomain.Release{}, err
	}
	return v, f.err
}

func TestReleaseCreationHTTPMapsFocusedDTOReplayAndPrivateErrors(t *testing.T) {
	local, secret := testServer(t)
	commands := &releaseCreationHTTPFake{}
	server, err := NewServerWithOptions(local.ledger, ServerOptions{ReleaseCreationCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"product_id":"uncached-product","version":"1.0.0"}`)
	response := postRaw(t, server, secret, "/v1/releases", "create-release", body, 201)
	if commands.calls != 1 || commands.actor.TenantID == "" || !reflect.DeepEqual(commands.input, releaseapp.CreateReleaseInput{ProductID: "uncached-product", Version: "1.0.0"}) {
		t.Fatal("focused release input changed", commands)
	}
	for _, field := range []string{`"id":"durable-release"`, `"tenant_id":"` + commands.actor.TenantID + `"`, `"product_id":"uncached-product"`, `"version":"1.0.0"`, `"state":"draft"`, `"revision":1`, `"created_at":"2026-01-02T03:04:05Z"`} {
		if !strings.Contains(response, field) {
			t.Fatal("release response lost field", field, response)
		}
	}
	if strings.Contains(response, `"frozen_at"`) || strings.Contains(response, `"approved_at"`) {
		t.Fatal("draft lifecycle field omission changed", response)
	}
	assertTrustHTTPReplay(t, response, postRaw(t, server, secret, "/v1/releases", "create-release", body, 201))
	if commands.calls != 1 {
		t.Fatal("release replay repeated command", commands.calls)
	}
	postRaw(t, server, secret, "/v1/releases", "create-release", append(body, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private release SQL"), 500}} {
		commands.err = tc.err
		failure := postRaw(t, server, secret, "/v1/releases", fmt.Sprintf("release-failure-%d", i), body, tc.status)
		if strings.Contains(failure, "private release SQL") || strings.Contains(failure, "durable-release") {
			t.Fatal("release failure leaked internals or result", failure)
		}
	}
}
