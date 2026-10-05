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

type sourceBranchHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	err      error
	input    integrationapp.UpsertSourceBranchInput
}

func (f *sourceBranchHTTPFake) AuthorizeSourceBranchUpsert(context.Context, identitydomain.Actor, integrationapp.UpsertSourceBranchInput) error {
	f.guards++
	return f.guardErr
}

func (f *sourceBranchHTTPFake) UpsertSourceBranch(_ context.Context, a identitydomain.Actor, in integrationapp.UpsertSourceBranchInput) (integrationdomain.SourceBranch, error) {
	f.calls++
	f.input = in
	return integrationdomain.SourceBranch{ID: "durable_branch", TenantID: a.TenantID, RepositoryID: in.RepositoryID, Name: in.Name, HeadCommitID: in.HeadCommitID, Protected: in.Protected, ProtectionHash: in.ProtectionHash, SchemaVersion: integrationdomain.SourceBranchSchemaVersion}, f.err
}
func TestSourceBranchHTTPUsesFocusedCommandAndPreservesReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &sourceBranchHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{SourceBranchCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"repository_id": "not-in-ledger", "name": "main", "head_commit_id": "durable-head", "protected": true, "protection_hash": "opaque"}
	body := postJSON(t, s, secret, "/v1/source/branches", "branch-replay", in, 201)
	if !strings.Contains(body, `"id":"durable_branch"`) || !strings.Contains(body, `"protected":true`) || f.calls != 1 || f.input.HeadCommitID != "durable-head" || f.input.ProtectionHash != "opaque" {
		t.Fatal(body, f)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/source/branches", "branch-replay", in, 201))
	if f.calls != 1 {
		t.Fatal("replay reran branch update", f)
	}
	postJSON(t, s, secret, "/v1/source/branches", "branch-replay", map[string]any{"repository_id": "different", "name": "main"}, 409)
	for i, raw := range []string{`null`, `[]`, `{"repository_id":null}`, `{"name":null}`, `{"head_commit_id":null}`, `{"protected":null}`, `{"protected":"true"}`, `{"protection_hash":null}`, `{"unknown":true}`, `{"name":"a","name":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/source/branches", fmt.Sprintf("bad-branch-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("bad input reached branch command", f.calls)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {errors.New("private source SQL"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/source/branches", fmt.Sprintf("failed-branch-%d", i), in, tc.status)
		if strings.Contains(body, "private source SQL") || strings.Contains(body, "durable_branch") {
			t.Fatal(body)
		}
	}
}
func TestSourceBranchOpenAPIDeclaresReplacementAndRecordingOnly(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/source/branches", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"before metadata", "same repository", "creation time", "same transaction", "2304", "does not verify"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing branch contract", description)
		}
	}
}
