package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type auditLogQueryFake struct {
	actor  identitydomain.Actor
	filter verificationquery.AuditFilter
	page   appquery.PageRequest
	calls  int
	err    error
}

func (f *auditLogQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, filter verificationquery.AuditFilter, page appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	f.actor, f.filter, f.page = actor, filter, page
	f.calls++
	if f.err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, f.err
	}
	return appquery.Result[verificationdomain.AuditChainEntry]{Items: []verificationdomain.AuditChainEntry{{
		ID: "ace_database", TenantID: actor.TenantID, SubjectType: "release", SubjectID: "rel_1",
		OccurredAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
	}}}, nil
}

func TestAuditLogHandlerUsesFocusedQueryAndRejectsMalformedFilters(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &auditLogQueryFake{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{AuditLogQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/audit-log?subject_type=release&subject_id=rel_1&since=2026-09-28T11%3A00%3A00Z&page_size=1", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			PageSize int `json:"page_size"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "ace_database" || page.Meta.PageSize != 1 || query.calls != 1 || query.actor.TenantID == "" || query.filter.SubjectID != "rel_1" || query.page.PageSize != 1 {
		t.Fatalf("focused audit response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/audit-log?subject_type=release&subject_type=product",
		"/v1/audit-log?since=not-a-time",
		"/v1/audit-log?limit=0",
		"/v1/audit-log?cursor=forged",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	if query.calls != 1 {
		t.Fatalf("malformed audit inputs reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: verificationquery.ErrValidation, status: http.StatusBadRequest},
	} {
		query.err = test.err
		getRaw(t, server, secret, "/v1/audit-log", test.status)
	}
}
