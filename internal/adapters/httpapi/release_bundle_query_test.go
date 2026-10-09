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
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type releaseBundleQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *releaseBundleQueryFake) GetReleaseBundle(_ context.Context, actor identitydomain.Actor, id string) (packagedomain.ReleaseBundle, error) {
	f.calls++
	f.actor, f.id = actor, id
	if f.err != nil {
		return packagedomain.ReleaseBundle{}, f.err
	}
	state, _ := packagedomain.ParseBundleState(packagedomain.BundleStateGeneratedValue)
	return packagedomain.ReleaseBundle{ID: id, TenantID: actor.TenantID, ReleaseID: "rel_database", State: state,
		Manifest: map[string]any{"private": "manifest"}, ManifestHash: "sha256:hash", SignatureRefs: []string{},
		CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}, nil
}

func TestReleaseBundleHandlersUseFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &releaseBundleQueryFake{}
	server.releaseBundleQuery = query
	response := getRaw(t, server, secret, "/v1/release-bundles/bun_database", http.StatusOK)
	var result struct {
		Data struct {
			ID       string         `json:"id"`
			State    string         `json:"state"`
			Manifest map[string]any `json:"manifest"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Data.ID != "bun_database" || result.Data.State != "generated" || result.Data.Manifest["private"] != "manifest" || query.calls != 1 || query.actor.TenantID == "" {
		t.Fatalf("bundle response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	response = getRaw(t, server, secret, "/v1/release-bundles/bun_database/manifest", http.StatusOK)
	var manifest struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &manifest); err != nil || manifest.Data["private"] != "manifest" || query.calls != 2 {
		t.Fatalf("manifest response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	getRawNoAuth(t, server, "/v1/release-bundles/bun_database/manifest", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("unauthenticated request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrValidation, http.StatusBadRequest},
		{packagequery.ErrReleaseBundleNotFound, http.StatusNotFound},
		{packagequery.ErrReleaseBundleProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-bundle-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		for _, route := range []string{"/v1/release-bundles/bun_database", "/v1/release-bundles/bun_database/manifest"} {
			response := getRaw(t, server, secret, route, test.status)
			if strings.Contains(response.Body.String(), "private-bundle-database-detail") {
				t.Fatalf("internal detail leaked: %s", response.Body.String())
			}
		}
	}
}
