package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type outboxDiagnosticsQueryFake struct {
	reads int
	err   error
}

func (f *outboxDiagnosticsQueryFake) Diagnostics(context.Context, identitydomain.Actor) (operationsquery.OutboxCounts, error) {
	f.reads++
	if f.err != nil {
		return operationsquery.OutboxCounts{}, f.err
	}
	return operationsquery.OutboxCounts{
		PendingJobs: 2, RunningJobs: 1, TerminalJobs: 3,
		OldestPendingCreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}, nil
}

func TestOutboxDiagnosticsHandlerUsesFocusedQueryWithoutLedgerOperator(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Instance", "instance-admin", []string{app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatal(err)
	}
	query := &outboxDiagnosticsQueryFake{}
	server.outboxDiagnosticsQuery = query
	response := getJSON(t, server, secret, "/v1/admin/outbox", http.StatusOK)
	if !strings.Contains(response, `"pending_jobs":2`) || strings.Contains(response, "payload") || strings.Contains(response, "failure_detail") || query.reads != 1 {
		t.Fatalf("unsafe or missing focused diagnostics: %s reads=%d", response, query.reads)
	}
}

func TestOutboxDiagnosticsHandlerMapsFocusedQueryErrors(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{
		{application.ErrForbidden, http.StatusForbidden},
		{operationsquery.ErrInvalidProjection, http.StatusConflict},
		{errors.New("private database detail"), http.StatusInternalServerError},
	} {
		ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
		_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Instance", "instance-admin", []string{app.ScopeInstanceAdmin})
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewServer(ledger)
		if err != nil {
			t.Fatal(err)
		}
		server.outboxDiagnosticsQuery = &outboxDiagnosticsQueryFake{err: test.err}
		response := getJSON(t, server, secret, "/v1/admin/outbox", test.status)
		if strings.Contains(response, "private database detail") {
			t.Fatalf("internal error leaked: %s", response)
		}
	}
}
