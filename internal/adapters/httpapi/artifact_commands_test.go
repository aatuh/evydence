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

type artifactHTTPFake struct {
	guards   int
	guardErr error
	calls    int
	actor    identitydomain.Actor
	input    releaseapp.RegisterArtifactInput
	err      error
}

func (f *artifactHTTPFake) AuthorizeArtifactRegistration(context.Context, identitydomain.Actor, releaseapp.RegisterArtifactInput) error {
	f.guards++
	return f.guardErr
}

func (f *artifactHTTPFake) RegisterArtifact(_ context.Context, actor identitydomain.Actor, in releaseapp.RegisterArtifactInput) (releasedomain.Artifact, error) {
	f.calls++
	f.actor, f.input = actor, in
	return releasedomain.Artifact{ID: "durable-artifact", TenantID: actor.TenantID, Name: in.Name, MediaType: in.MediaType, Digest: in.Digest, Size: in.Size, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, f.err
}

func TestArtifactHTTPMapsFocusedDTOReplayAndPrivateErrors(t *testing.T) {
	local, secret := testServer(t)
	commands := &artifactHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(local), ServerOptions{ArtifactCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	body := []byte(`{"name":"Release artifact","media_type":"application/octet-stream","digest":"` + digest + `","size":123}`)
	response := postRaw(t, server, secret, "/v1/artifacts", "create-artifact", body, 201)
	want := releaseapp.RegisterArtifactInput{Name: "Release artifact", MediaType: "application/octet-stream", Digest: digest, Size: 123}
	if commands.calls != 1 || commands.actor.TenantID == "" || !reflect.DeepEqual(commands.input, want) {
		t.Fatal("focused artifact input changed", commands)
	}
	for _, field := range []string{`"id":"durable-artifact"`, `"tenant_id":"` + commands.actor.TenantID + `"`, `"name":"Release artifact"`, `"media_type":"application/octet-stream"`, `"digest":"` + digest + `"`, `"size":123`, `"created_at":"2026-01-02T03:04:05Z"`} {
		if !strings.Contains(response, field) {
			t.Fatal("artifact response lost field", field, response)
		}
	}
	assertTrustHTTPReplay(t, response, postRaw(t, server, secret, "/v1/artifacts", "create-artifact", body, 201))
	if commands.calls != 1 {
		t.Fatal("artifact replay repeated command", commands.calls)
	}
	postRaw(t, server, secret, "/v1/artifacts", "create-artifact", append(body, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private artifact SQL"), 500}} {
		commands.err = tc.err
		failure := postRaw(t, server, secret, "/v1/artifacts", fmt.Sprintf("artifact-failure-%d", i), body, tc.status)
		if strings.Contains(failure, "private artifact SQL") || strings.Contains(failure, "durable-artifact") {
			t.Fatal("artifact failure leaked internal detail or result", failure)
		}
	}
	commands.err = nil
	postRaw(t, server, secret, "/v1/artifacts", "omitted-artifact-size", []byte(`{"name":"empty","media_type":"text/plain","digest":"`+digest+`"}`), 201)
	if commands.input.Size != 0 {
		t.Fatal("omitted size default changed", commands.input)
	}
}
