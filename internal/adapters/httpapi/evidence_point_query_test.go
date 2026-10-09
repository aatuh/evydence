package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidencePointQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
	kind  string
}

func (f *evidencePointQueryFake) GetEvidence(_ context.Context, actor identitydomain.Actor, id string) (evidencedomain.EvidenceItem, error) {
	f.actor, f.id = actor, id
	f.calls++
	if f.err != nil {
		return evidencedomain.EvidenceItem{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	kind := f.kind
	if kind == "" {
		kind = "document"
	}
	return evidencedomain.EvidenceItem{ID: id, TenantID: actor.TenantID, ProductID: "prod_database", Type: kind, Title: "Evidence", SourceSystem: "api", ObservedAt: now, EvidenceVersion: 1, SchemaVersion: "v1", PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical", Canonicalization: "canonical-json.v1", TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now}, nil
}

func TestEvidencePointHandlerUsesFocusedQueryWithoutProductionFallback(t *testing.T) {
	server, secret := testServer(t)
	query := &evidencePointQueryFake{}
	server.evidencePointQuery = query
	response := getRaw(t, server, secret, "/v1/evidence/ev_database_only", http.StatusOK)
	var item struct {
		Data struct {
			ID        string `json:"id"`
			ProductID string `json:"product_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &item); err != nil || item.Data.ID != "ev_database_only" || item.Data.ProductID != "prod_database" || query.id != "ev_database_only" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("focused evidence response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	getRawNoAuth(t, server, "/v1/evidence/ev_database_only", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated request reached evidence query %d times", query.calls)
	}
	if reflect.ValueOf(server).Elem().FieldByName("evidenceIngestion").IsValid() {
		t.Fatal("retired broad Evidence binding remains")
	}
	query.kind = "parser_normalization"
	response = getRaw(t, server, secret, "/v1/evidence/ev_worker", http.StatusOK)
	if query.id != "ev_worker" || !strings.Contains(response.Body.String(), `"parser_normalization"`) {
		t.Fatalf("worker projection lost focused query result: response=%s", response.Body.String())
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: evidencequery.ErrNotFound, status: http.StatusNotFound},
		{err: evidencequery.ErrValidation, status: http.StatusBadRequest},
		{err: evidencequery.ErrConflict, status: http.StatusConflict},
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: errors.New("postgres-private-detail"), status: http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/evidence/ev_database_only", test.status)
		if strings.Contains(response.Body.String(), "postgres") {
			t.Fatalf("internal detail in evidence error: %s", response.Body.String())
		}
	}
	// Even legacy characterization fixtures must supply the focused port.
	query.err, query.kind = nil, "document"
	response = getRaw(t, server, secret, "/v1/evidence/ev_local", http.StatusOK)
	if query.id != "ev_local" || !strings.Contains(response.Body.String(), `"id":"ev_local"`) {
		t.Fatal("fixture point read bypassed the required focused query")
	}
}
