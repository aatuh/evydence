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

type environmentCommandHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	err      error
	input    operationsapp.CreateEnvironmentInput
}

func (f *environmentCommandHTTPFake) AuthorizeEnvironmentCreation(context.Context, identitydomain.Actor, operationsapp.CreateEnvironmentInput) error {
	f.guards++
	return f.guardErr
}

func TestDeploymentEnvironmentOpenAPIDeclaresDurableNameReuse(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/environments", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"returns the original", "same transaction", "1024 bytes", "2304 bytes", "not proof"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing environment contract", description)
		}
	}
}
func (f *environmentCommandHTTPFake) CreateDeploymentEnvironment(_ context.Context, a identitydomain.Actor, in operationsapp.CreateEnvironmentInput) (operationsdomain.DeploymentEnvironment, error) {
	f.calls++
	f.input = in
	return operationsdomain.DeploymentEnvironment{ID: "durable_environment", TenantID: a.TenantID, ProductID: in.ProductID, Name: in.Name, Kind: in.Kind, SchemaVersion: operationsdomain.DeploymentEnvironmentVersion}, f.err
}
func TestDeploymentEnvironmentHTTPUsesFocusedCommandAndSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &environmentCommandHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{DeploymentEnvironmentCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"product_id": "not-in-ledger", "name": "Production", "kind": "production"}
	body := postJSON(t, s, secret, "/v1/environments", "environment-replay", in, 201)
	if !strings.Contains(body, `"id":"durable_environment"`) || f.calls != 1 || f.input.ProductID != "not-in-ledger" {
		t.Fatal(body, f)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/environments", "environment-replay", in, 201))
	if f.calls != 1 {
		t.Fatal("replay reran creation", f)
	}
	for i, raw := range []string{`null`, `[]`, `{"name":null}`, `{"unknown":true}`, `{"name":"a","name":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/environments", fmt.Sprintf("bad-env-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed envelope reached command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{operationsapp.ErrValidation, 400}, {operationsapp.ErrNotFound, 404}, {operationsapp.ErrConflict, 409}, {errors.New("private SQL row"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/environments", fmt.Sprintf("failed-env-%d", i), in, tc.status)
		if strings.Contains(body, "private SQL") || strings.Contains(body, "durable_environment") {
			t.Fatal(body)
		}
	}
}
