package httpapi

import (
	"context"
	"encoding/json"
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

type buildPointQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *buildPointQueryFake) GetBuildRun(_ context.Context, actor identitydomain.Actor, id string) (releasedomain.BuildRun, error) {
	f.actor, f.id = actor, id
	f.calls++
	if f.err != nil {
		return releasedomain.BuildRun{}, f.err
	}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	return releasedomain.BuildRun{
		ID: id, TenantID: actor.TenantID, ProjectID: "proj_database", ReleaseID: "rel_database",
		Provider: "github", CommitSHA: "0123456789abcdef", Status: "completed", StartedAt: now,
		SourceIdentity: map[string]any{"issuer": "test"},
		Outputs:        []releasedomain.BuildOutput{{ArtifactID: "art_1", Digest: "sha256:output"}},
		SchemaVersion:  "v1", CreatedAt: now,
	}, nil
}

func TestBuildPointHandlerUsesFocusedQueryAndMapsErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &buildPointQueryFake{}
	server.buildPointQuery = query
	response := getRaw(t, server, secret, "/v1/builds/bld_database_only", http.StatusOK)
	var build struct {
		Data struct {
			ID      string `json:"id"`
			Outputs []struct {
				ArtifactID string `json:"artifact_id"`
			} `json:"outputs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &build); err != nil || build.Data.ID != "bld_database_only" || len(build.Data.Outputs) != 1 || build.Data.Outputs[0].ArtifactID != "art_1" || query.id != "bld_database_only" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("focused build response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	getRawNoAuth(t, server, "/v1/builds/bld_database_only", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated request reached build query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: releasequery.ErrNotFound, status: http.StatusNotFound},
		{err: releasequery.ErrValidation, status: http.StatusBadRequest},
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: errors.New("postgres-private-detail"), status: http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/builds/bld_database_only", test.status)
		if strings.Contains(response.Body.String(), "postgres") {
			t.Fatalf("internal detail in build error: %s", response.Body.String())
		}
	}
}
