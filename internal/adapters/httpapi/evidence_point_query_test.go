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
	"github.com/aatuh/evydence/internal/domain"
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

type evidenceProjectionFallbackFake struct {
	evidenceIngestionService
	calls          int
	id             string
	lifecycleCalls int
}

func (f *evidenceProjectionFallbackFake) GetEvidence(_ context.Context, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	f.calls++
	f.id = id
	return domain.EvidenceItem{ID: id, TenantID: actor.TenantID, Type: "parser_normalization", Title: "Parser normalization replay"}, nil
}

func (f *evidenceProjectionFallbackFake) ListEvidenceLifecycleEvents(_ context.Context, _ domain.Actor, _ string) ([]domain.EvidenceLifecycleEvent, error) {
	f.lifecycleCalls++
	return []domain.EvidenceLifecycleEvent{}, nil
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
	fallback := &evidenceProjectionFallbackFake{}
	server.evidenceIngestion = fallback
	query.kind = "parser_normalization"
	response = getRaw(t, server, secret, "/v1/evidence/ev_worker", http.StatusOK)
	if fallback.calls != 0 || query.id != "ev_worker" || !strings.Contains(response.Body.String(), `"parser_normalization"`) {
		t.Fatalf("worker projection used compatibility aggregate: response=%s calls=%d", response.Body.String(), fallback.calls)
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
	if fallback.calls != 0 {
		t.Fatal("query failure invoked compatibility aggregate")
	}
	// Only the explicit local-memory profile, with no durable query bound,
	// retains the existing compatibility read behavior.
	server.evidencePointQuery = nil
	getRaw(t, server, secret, "/v1/evidence/ev_local", http.StatusOK)
	if fallback.calls != 1 {
		t.Fatal("local-memory compatibility path removed")
	}
}
