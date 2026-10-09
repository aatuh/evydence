package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type containerImageHTTPFake struct {
	guards   int
	guardErr error
	calls    int
	actor    identitydomain.Actor
	input    releaseapp.RegisterContainerImageInput
	err      error
}

func (f *containerImageHTTPFake) AuthorizeContainerImageRegistration(context.Context, identitydomain.Actor, releaseapp.RegisterContainerImageInput) error {
	f.guards++
	return f.guardErr
}

func (f *containerImageHTTPFake) RegisterContainerImage(_ context.Context, actor identitydomain.Actor, in releaseapp.RegisterContainerImageInput) (releasedomain.ContainerImage, error) {
	f.calls++
	f.actor, f.input = actor, in
	return releasedomain.ContainerImage{ID: "durable-image", TenantID: actor.TenantID, ArtifactID: in.ArtifactID, Repository: in.Repository, Tag: in.Tag, Digest: in.Digest, Platform: in.Platform}, f.err
}

func TestContainerImageHTTPMapsFocusedDTOAndPrivateErrors(t *testing.T) {
	local, secret := testServer(t)
	commands := &containerImageHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(local), ServerOptions{ContainerImageCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	body := []byte(`{"artifact_id":"uncached-artifact","repository":"registry.example.test/api","tag":"v1","digest":"` + digest + `","platform":"linux/amd64"}`)
	response := postRaw(t, server, secret, "/v1/container-images", "create-image", body, 201)
	want := releaseapp.RegisterContainerImageInput{ArtifactID: "uncached-artifact", Repository: "registry.example.test/api", Tag: "v1", Digest: digest, Platform: "linux/amd64"}
	if commands.calls != 1 || commands.actor.TenantID == "" || !reflect.DeepEqual(commands.input, want) || !strings.Contains(response, `"id":"durable-image"`) || !strings.Contains(response, `"tag":"v1"`) {
		t.Fatal("focused DTO mapping changed", commands, response)
	}
	assertTrustHTTPReplay(t, response, postRaw(t, server, secret, "/v1/container-images", "create-image", body, 201))
	if commands.calls != 1 {
		t.Fatal("replay repeated command", commands.calls)
	}
	postRaw(t, server, secret, "/v1/container-images", "create-image", append(body, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private SQL secret"), 500}} {
		commands.err = tc.err
		failure := postRaw(t, server, secret, "/v1/container-images", fmt.Sprintf("failure-%d", i), body, tc.status)
		if strings.Contains(failure, "private SQL") || strings.Contains(failure, "durable-image") {
			t.Fatal("error leaked backend detail or unsuccessful result", failure)
		}
	}
	commands.err = nil
	omitted := postRaw(t, server, secret, "/v1/container-images", "omitted-fields", []byte(`{"repository":"registry.example.test/detached","digest":"`+digest+`"}`), 201)
	if strings.Contains(omitted, `"artifact_id"`) || strings.Contains(omitted, `"tag"`) || strings.Contains(omitted, `"platform"`) {
		t.Fatal("optional field omission changed", omitted)
	}
}
