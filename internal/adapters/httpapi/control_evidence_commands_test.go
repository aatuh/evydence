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

type controlEvidenceCommandFake struct {
	calls int
	actor identitydomain.Actor
	id    string
	input riskapp.LinkControlEvidenceInput
	err   error
	value riskdomain.ControlEvidence
}

func (f *controlEvidenceCommandFake) LinkControlEvidence(_ context.Context, actor identitydomain.Actor, id string, in riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error) {
	f.calls++
	f.actor, f.id, f.input = actor, id, in
	return f.value, f.err
}

func TestControlEvidenceHTTPUsesNarrowCommandAndMapsDTOAndErrors(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	tenant, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	value := riskdomain.ControlEvidence{ID: "link", TenantID: tenant.ID, ControlID: "control", EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom", ProductID: "product", ReleaseID: "release", Confidence: "medium", Notes: "reviewed", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	commands := &controlEvidenceCommandFake{value: value}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{ControlEvidenceCommands: commands})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/controls/control/evidence"
	body := `{"evidence_type":"sbom","subject_type":"sbom","subject_id":"sbom","product_id":"product","release_id":"release","confidence":"medium","notes":"reviewed"}`
	var envelope struct {
		Data domain.ControlEvidence `json:"data"`
	}
	if err := json.Unmarshal([]byte(postRaw(t, server, secret, path, "link", []byte(body), 201)), &envelope); err != nil || envelope.Data != controlEvidenceFromQuery(value) || commands.calls != 1 || commands.actor.TenantID != tenant.ID || commands.actor.KeyID == "" || commands.id != "control" || commands.input != (riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom", ProductID: "product", ReleaseID: "release", Confidence: "medium", Notes: "reviewed"}) {
		t.Fatal("focused command lost principal, inputs, or DTO", envelope, commands, err)
	}
	for i, bad := range []string{"{", "[]", "null", body + " {}", strings.ReplaceAll(body, `"notes":"reviewed"`, `"notes":null`), strings.ReplaceAll(body, `"product_id":"product"`, `"product_id":null`), strings.ReplaceAll(body, `"release_id":"release"`, `"release_id":null`), strings.ReplaceAll(body, `"notes":"reviewed"`, `"notes":1`), strings.ReplaceAll(body, `"notes":"reviewed"`, `"notes":"a","notes":"b"`), strings.ReplaceAll(body, `"notes":"reviewed"`, `"tenant_id":"foreign"`)} {
		postRaw(t, server, secret, path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
	}
	for i, id := range []string{"bad%00id", "%FF", strings.Repeat("x", 1025)} {
		postRaw(t, server, secret, "/v1/controls/"+id+"/evidence", fmt.Sprintf("bad-id-%d", i), []byte(body), 400)
	}
	postRaw(t, server, "", path, "no-auth", []byte(body), 401)
	if commands.calls != 1 {
		t.Fatal("invalid requests reached focused command", commands.calls)
	}
	for i, test := range []struct {
		err    error
		status int
	}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private control linking details"), 500}} {
		commands.err = fmt.Errorf("wrapped: %w", test.err)
		response := postRaw(t, server, secret, path, fmt.Sprintf("error-%d", i), []byte(body), test.status)
		if strings.Contains(response, "private control linking details") {
			t.Fatal("private command error leaked", response)
		}
	}
	if commands.calls != 7 {
		t.Fatal("command errors not exercised", commands.calls)
	}
}
