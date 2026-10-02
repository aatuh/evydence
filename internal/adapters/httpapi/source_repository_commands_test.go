package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type sourceCreationHTTPFake struct {
	calls int
	err   error
	input integrationapp.CreateSourceRepositoryInput
}

func (f *sourceCreationHTTPFake) CreateSourceRepository(_ context.Context, a identitydomain.Actor, in integrationapp.CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	f.calls++
	f.input = in
	return integrationdomain.SourceRepository{ID: "durable_repository", TenantID: a.TenantID, ProjectID: in.ProjectID, Provider: in.Provider, FullName: in.FullName, SchemaVersion: integrationdomain.SourceRepositorySchemaVersion}, f.err
}
func TestSourceRepositoryHTTPUsesFocusedCommandAndRejectsMalformedEnvelopes(t *testing.T) {
	local, secret := testServer(t)
	f := &sourceCreationHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{SourceRepositoryCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"project_id": "not-in-ledger", "provider": "github", "full_name": "org/api"}
	body := postJSON(t, s, secret, "/v1/source/repositories", "source-replay", in, 201)
	if !strings.Contains(body, `"id":"durable_repository"`) || f.calls != 1 || f.input.ProjectID != "not-in-ledger" {
		t.Fatal(body, f)
	}
	if again := postJSON(t, s, secret, "/v1/source/repositories", "source-replay", in, 201); again != body || f.calls != 1 {
		t.Fatal("replay reran creation", f)
	}
	for i, raw := range []string{`null`, `[]`, `{"provider":null}`, `{"project_id":null}`, `{"clone_url":null}`, `{"unknown":true}`, `{"provider":"a","provider":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/source/repositories", fmt.Sprintf("bad-source-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("bad envelope reached source command", f.calls)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {errors.New("private repository SQL"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/source/repositories", fmt.Sprintf("failed-source-%d", i), in, tc.status)
		if strings.Contains(body, "private repository SQL") || strings.Contains(body, "durable_repository") {
			t.Fatal(body)
		}
	}
}
func TestSourceRepositoryOpenAPIDeclaresOwnershipAndMetadataOnlyRecording(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/source/repositories", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"existing repository", "before metadata", "2304", "same transaction", "does not contact"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing source repository contract", description)
		}
	}
}
