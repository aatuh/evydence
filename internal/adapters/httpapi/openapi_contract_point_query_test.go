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

type openAPIContractPointQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *openAPIContractPointQueryFake) GetOpenAPIContract(_ context.Context, actor identitydomain.Actor, id string) (evidencedomain.OpenAPIContract, error) {
	f.calls++
	f.actor, f.id = actor, id
	if f.err != nil {
		return evidencedomain.OpenAPIContract{}, f.err
	}
	return evidencedomain.OpenAPIContract{ID: id, TenantID: actor.TenantID, ProductID: "prod_1", EvidenceID: "ev_1", Version: "1.0",
		Hash:       "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		Operations: []evidencedomain.OpenAPIOperation{{Path: "/v1/items", Method: "GET", OperationID: "listItems"}},
		CreatedAt:  time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}, nil
}

func TestOpenAPIContractHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &openAPIContractPointQueryFake{}
	server.openAPIContractPointQuery = query
	response := getRaw(t, server, secret, "/v1/openapi-contracts/con_database", http.StatusOK)
	if !strings.Contains(response.Body.String(), `"operation_id":"listItems"`) || query.id != "con_database" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("contract response=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, "/v1/openapi-contracts/con_database", http.StatusUnauthorized)
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
		{errors.New("private-contract-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/openapi-contracts/con_database", test.status)
		if strings.Contains(response.Body.String(), "private-contract-database-detail") {
			t.Fatalf("internal detail leaked: %s", response.Body.String())
		}
	}
}
