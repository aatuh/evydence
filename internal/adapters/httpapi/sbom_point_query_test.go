package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sbomPointQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *sbomPointQueryFake) GetSBOM(_ context.Context, actor identitydomain.Actor, id string) (evidencedomain.SBOM, error) {
	f.calls++
	f.actor, f.id = actor, id
	if f.err != nil {
		return evidencedomain.SBOM{}, f.err
	}
	return evidencedomain.SBOM{ID: id, TenantID: actor.TenantID, EvidenceID: "ev_1", ReleaseID: "rel_1", Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, Components: []evidencedomain.SBOMComponent{{Name: "openssl", Version: "3.0"}}, CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}, nil
}

func TestSBOMHandlerUsesFocusedPointAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &sbomPointQueryFake{}
	server.sbomPointQuery = query
	response := getRaw(t, server, secret, "/v1/sboms/sbom_database", http.StatusOK)
	if !strings.Contains(response.Body.String(), `"name":"openssl"`) || query.id != "sbom_database" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("SBOM response=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, "/v1/sboms/sbom_database", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated query calls=%d", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{evidencequery.ErrValidation, http.StatusBadRequest},
		{evidencequery.ErrNotFound, http.StatusNotFound},
		{evidencequery.ErrConflict, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-sbom-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/sboms/sbom_database", test.status)
		if strings.Contains(response.Body.String(), "private-sbom-database-detail") {
			t.Fatalf("internal detail leaked: %s", response.Body.String())
		}
	}
}
