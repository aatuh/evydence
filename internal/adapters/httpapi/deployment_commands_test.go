package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type deploymentHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	input    operationsapp.RecordDeploymentInput
	err      error
}

func (f *deploymentHTTPFake) AuthorizeDeploymentRecording(context.Context, identitydomain.Actor, operationsapp.RecordDeploymentInput) error {
	f.guards++
	return f.guardErr
}

func (f *deploymentHTTPFake) RecordDeployment(_ context.Context, a identitydomain.Actor, in operationsapp.RecordDeploymentInput) (operationsdomain.DeploymentEvent, error) {
	f.calls++
	f.input = in
	return operationsdomain.DeploymentEvent{ID: "durable_deployment", TenantID: a.TenantID, EnvironmentID: in.EnvironmentID, ReleaseID: in.ReleaseID, Status: in.Status, EvidenceID: "durable_evidence", SchemaVersion: operationsdomain.DeploymentEventSchemaVersion}, f.err
}
func TestDeploymentHTTPUsesFocusedCommandAndSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &deploymentHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{DeploymentCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"environment_id": "not-in-ledger", "release_id": "release", "status": "succeeded"}
	body := postJSON(t, s, secret, "/v1/deployments", "deployment-replay", in, 201)
	if !strings.Contains(body, `"evidence_id":"durable_evidence"`) || f.calls != 1 || f.input.EnvironmentID != "not-in-ledger" {
		t.Fatal(body, f)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/deployments", "deployment-replay", in, 201))
	if f.calls != 1 {
		t.Fatal("replay reran command", f)
	}
	for i, raw := range []string{`null`, `[]`, `{"status":null}`, `{"artifact_ids":[null]}`, `{"artifact_ids":null}`, `{"finished_at":null}`, `{"unknown":true}`, `{"status":"a","status":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/deployments", fmt.Sprintf("bad-deployment-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed input reached command", f.calls)
	}
	for i, tc := range []struct {
		err  error
		code int
	}{{operationsapp.ErrValidation, 400}, {operationsapp.ErrNotFound, 404}, {operationsapp.ErrConflict, 409}, {errors.New("private deployment SQL"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/deployments", fmt.Sprintf("failed-deployment-%d", i), in, tc.code)
		if strings.Contains(body, "private deployment SQL") || strings.Contains(body, "durable_evidence") {
			t.Fatal(body)
		}
	}
}
func TestDeploymentOpenAPIPreservesImmediateEvidenceAndOptionalStart(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/deployments", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"immediately readable", "same transaction", "1024", "not prove"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing deployment contract", description)
		}
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, doc["components"])["schemas"])
	schema := asStringAnyMap(t, schemas["RecordDeploymentRequest"])
	for _, required := range schema["required"].([]any) {
		if required == "started_at" {
			t.Fatal("optional server-default start declared mandatory")
		}
	}
}
