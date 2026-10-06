package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type approvalHTTPFake struct {
	actor                 identitydomain.Actor
	input                 riskapp.CreateApprovalInput
	value                 riskdomain.ApprovalRecord
	calls, authorizations int
	err                   error
}

func (f *approvalHTTPFake) AuthorizeApproval(_ context.Context, a identitydomain.Actor, input riskapp.CreateApprovalInput) error {
	f.authorizations++
	f.actor, f.input = a, input
	return f.err
}
func (f *approvalHTTPFake) CreateApprovalRecord(_ context.Context, a identitydomain.Actor, input riskapp.CreateApprovalInput) (riskdomain.ApprovalRecord, error) {
	f.calls++
	f.actor, f.input = a, input
	return f.value, f.err
}

func TestApprovalHTTPUsesNarrowPortAndPreservesDTOAndSafeErrors(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	tenant, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	f := &approvalHTTPFake{value: riskdomain.ApprovalRecord{ID: "approval", TenantID: tenant.ID, SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: "Review", ApproverID: "human", EvidenceID: "evidence", SchemaVersion: riskdomain.ApprovalRecordSchemaVersion, CreatedAt: now}}
	if _, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{ApprovalCommands: f}); err == nil {
		t.Fatal("approval silently used Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{ApprovalCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"subject_type":"release","subject_id":"release","decision":"approved","reason":"Review","evidence_id":"evidence"}`
	var v struct {
		Data domain.ApprovalRecord `json:"data"`
	}
	response := postRaw(t, server, secret, "/v1/approvals", "approval", []byte(body), 201)
	if err := json.Unmarshal([]byte(response), &v); err != nil || v.Data.ID != f.value.ID || v.Data.Reason != f.value.Reason || v.Data.CreatedAt != now || v.Data.TenantID != tenant.ID || v.Data.EvidenceID != "evidence" || f.actor.KeyID == "" || f.actor.TenantID != tenant.ID || f.calls != 1 || f.authorizations != 1 || f.input != (riskapp.CreateApprovalInput{SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: "Review", EvidenceID: "evidence"}) {
		t.Fatal("approval lost input, authenticated identity, or response metadata", response, err)
	}
	postRaw(t, server, "", "/v1/approvals", "unauthorized", []byte(body), 401)
	if executor.calls != 1 {
		t.Fatal("unauthenticated approval began a transaction")
	}
	for i, test := range []struct {
		err  error
		code int
	}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private approval detail"), 500}} {
		f.err = fmt.Errorf("wrapped: %w", test.err)
		response := postRaw(t, server, secret, "/v1/approvals", fmt.Sprintf("error-%d", i), []byte(body), test.code)
		if strings.Contains(response, "private") {
			t.Fatal("private approval error leaked", response)
		}
	}
}
