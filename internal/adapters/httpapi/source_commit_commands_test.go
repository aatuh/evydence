package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type sourceCommitHTTPFake struct {
	calls int
	err   error
	input integrationapp.RecordSourceCommitInput
}

func (f *sourceCommitHTTPFake) RecordSourceCommit(_ context.Context, a identitydomain.Actor, in integrationapp.RecordSourceCommitInput) (integrationdomain.SourceCommit, error) {
	f.calls++
	f.input = in
	return integrationdomain.SourceCommit{ID: "durable_commit", TenantID: a.TenantID, RepositoryID: in.RepositoryID, SHA: in.SHA, SchemaVersion: integrationdomain.SourceCommitSchemaVersion}, f.err
}
func TestSourceCommitHTTPUsesFocusedCommandAndRejectsMalformedEnvelopes(t *testing.T) {
	local, secret := testServer(t)
	f := &sourceCommitHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{SourceCommitCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"repository_id": "not-in-ledger", "sha": strings.Repeat("a", 40), "message": " sensitive message "}
	body := postJSON(t, s, secret, "/v1/source/commits", "commit-replay", in, 201)
	if !strings.Contains(body, `"id":"durable_commit"`) || strings.Contains(body, "sensitive message") || f.calls != 1 || f.input.RepositoryID != "not-in-ledger" || f.input.Message != " sensitive message " || !f.input.CommittedAt.IsZero() {
		t.Fatal(body, f)
	}
	if again := postJSON(t, s, secret, "/v1/source/commits", "commit-replay", in, 201); again != body || f.calls != 1 {
		t.Fatal("replay reran commit command", f)
	}
	postJSON(t, s, secret, "/v1/source/commits", "commit-replay", map[string]any{"repository_id": "different"}, 409)
	for i, raw := range []string{`null`, `[]`, `{"repository_id":null}`, `{"sha":null}`, `{"message":null}`, `{"author":null}`, `{"committed_at":null}`, `{"committed_at":"not-a-date"}`, `{"sha":17}`, `{"unknown":true}`, `{"sha":"a","sha":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/source/commits", fmt.Sprintf("bad-commit-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("invalid envelope reached command", f.calls)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {errors.New("private commit SQL"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/source/commits", fmt.Sprintf("failed-commit-%d", i), in, tc.status)
		if strings.Contains(body, "private commit SQL") || strings.Contains(body, "durable_commit") || strings.Contains(body, "sensitive message") {
			t.Fatal(body)
		}
	}
}
func TestSourceCommitOpenAPIDeclaresOptionalTimestampAndImmutableReuse(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, doc["components"])["schemas"])
	request := asStringAnyMap(t, schemas["RecordSourceCommitRequest"])
	for _, v := range request["required"].([]any) {
		if v == "committed_at" {
			t.Fatal("optional runtime timestamp required in schema")
		}
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/source/commits", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"lowercase", "before metadata", "same transaction", "exact", "omitted", "does not verify"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing commit contract", description)
		}
	}
}
