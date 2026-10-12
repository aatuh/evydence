package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type evidenceFlowQueryFake struct {
	tenantID  string
	releaseID string
	err       error
}

func (f *evidenceFlowQueryFake) Plan(_ context.Context, actor identitydomain.Actor, id string) (releasedomain.ReleaseEvidenceFlow, error) {
	f.tenantID, f.releaseID = actor.TenantID, id
	if f.err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, f.err
	}
	return releasequery.AssembleEvidenceFlow(id, "prod_database", map[string]int{
		"artifact_refs": 1, "passed_builds": 1, "sboms": 1,
		"vulnerability_scans": 1, "release_bundles": 1,
	}, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)), nil
}

func TestReleaseEvidenceFlowHandlerUsesFocusedQueryWithoutLedgerRelease(t *testing.T) {
	server, secret := testServer(t)
	query := &evidenceFlowQueryFake{}
	server.evidenceFlowQuery = query
	body := postJSON(t, server, secret, "/v1/releases/rel_database_only/evidence-flow/start", "flow-database", map[string]any{}, http.StatusOK)
	for _, want := range []string{`"release_id":"rel_database_only"`, `"product_id":"prod_database"`, `"status":"ready_for_review"`, `"artifact_refs":1`, `"path":"/v1/sboms"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("focused flow response missing %s: %s", want, body)
		}
	}
	if query.tenantID == "" || query.releaseID != "rel_database_only" {
		t.Fatalf("focused query not called with tenant and release: %#v", query)
	}
}

func TestReleaseEvidenceFlowReadOnlyPostAcceptsNoIdempotencyKey(t *testing.T) {
	server, secret := testServer(t)
	server.evidenceFlowQuery = &evidenceFlowQueryFake{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/releases/rel_database_only/evidence-flow/start", bytes.NewReader([]byte("{}")))
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("read-only flow without idempotency key status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestReleaseEvidenceFlowHandlerMapsFocusedQueryErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"missing", releasequery.ErrNotFound, http.StatusNotFound},
		{"forbidden", application.ErrForbidden, http.StatusForbidden},
		{"invalid", releasequery.ErrValidation, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, secret := testServer(t)
			server.evidenceFlowQuery = &evidenceFlowQueryFake{err: test.err}
			postJSON(t, server, secret, "/v1/releases/rel_database_only/evidence-flow/start", "flow-"+test.name, map[string]any{}, test.status)
		})
	}
}
