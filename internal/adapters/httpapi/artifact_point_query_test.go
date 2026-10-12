package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type artifactPointQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *artifactPointQueryFake) GetArtifact(_ context.Context, actor identitydomain.Actor, id string) (releasedomain.Artifact, error) {
	f.calls++
	f.actor, f.id = actor, id
	if f.err != nil {
		return releasedomain.Artifact{}, f.err
	}
	return releasedomain.Artifact{ID: id, TenantID: actor.TenantID, Name: "artifact", MediaType: "application/octet-stream", Size: 1,
		Digest:    "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}, nil
}

func TestArtifactHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &artifactPointQueryFake{}
	server.artifactPointQuery = query
	response := getRaw(t, server, secret, "/v1/artifacts/art_database", http.StatusOK)
	if !strings.Contains(response.Body.String(), `"id":"art_database"`) || query.id != "art_database" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("artifact response=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, "/v1/artifacts/art_database", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated query calls=%d", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{releasequery.ErrValidation, http.StatusBadRequest},
		{releasequery.ErrNotFound, http.StatusNotFound},
		{releasequery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-artifact-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/artifacts/art_database", test.status)
		if strings.Contains(response.Body.String(), "private-artifact-database-detail") {
			t.Fatalf("internal detail leaked: %s", response.Body.String())
		}
	}
}
