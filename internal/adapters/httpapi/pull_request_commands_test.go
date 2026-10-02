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

type pullRequestHTTPFake struct {
	calls int
	err   error
	input integrationapp.RecordPullRequestInput
}

func (f *pullRequestHTTPFake) RecordPullRequest(_ context.Context, a identitydomain.Actor, in integrationapp.RecordPullRequestInput) (integrationdomain.PullRequest, error) {
	f.calls++
	f.input = in
	return integrationdomain.PullRequest{ID: "durable_pr", TenantID: a.TenantID, RepositoryID: in.RepositoryID, Provider: "default_provider", ProviderID: in.ProviderID, Title: in.Title, State: in.State, SchemaVersion: integrationdomain.PullRequestSchemaVersion}, f.err
}
func TestPullRequestHTTPUsesFocusedCommandAndRejectsMalformedEnvelopes(t *testing.T) {
	local, secret := testServer(t)
	f := &pullRequestHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{PullRequestCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"repository_id": "not-in-ledger", "provider_id": "17", "title": "Change", "state": "open"}
	body := postJSON(t, s, secret, "/v1/source/pull-requests", "pr-replay", in, 201)
	if !strings.Contains(body, `"id":"durable_pr"`) || f.calls != 1 || f.input.Provider != "" || f.input.RepositoryID != "not-in-ledger" {
		t.Fatal(body, f)
	}
	if again := postJSON(t, s, secret, "/v1/source/pull-requests", "pr-replay", in, 201); again != body || f.calls != 1 {
		t.Fatal("replay reran recording", f)
	}
	postJSON(t, s, secret, "/v1/source/pull-requests", "pr-replay", map[string]any{"title": "changed"}, 409)
	for i, raw := range []string{`null`, `[]`, `{"repository_id":null}`, `{"provider":null}`, `{"provider_id":null}`, `{"title":null}`, `{"state":null}`, `{"source_branch":null}`, `{"target_branch":null}`, `{"head_commit_id":null}`, `{"review_decision":null}`, `{"state":17}`, `{"unknown":true}`, `{"title":"a","title":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/source/pull-requests", fmt.Sprintf("bad-pr-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("invalid envelope reached command", f.calls)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {errors.New("private pull request SQL"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/source/pull-requests", fmt.Sprintf("failed-pr-%d", i), in, tc.status)
		if strings.Contains(body, "private pull request SQL") || strings.Contains(body, "durable_pr") {
			t.Fatal(body)
		}
	}
}
func TestPullRequestOpenAPIMatchesProviderDefaultAndAppendOnlySnapshots(t *testing.T) {
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
	request := asStringAnyMap(t, schemas["RecordPullRequestRequest"])
	for _, v := range request["required"].([]any) {
		if v == "provider" {
			t.Fatal("defaulted provider required by schema")
		}
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/source/pull-requests", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"before metadata", "same repository", "new snapshot", "same transaction", "omitted provider", "does not verify"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing pull request contract", description)
		}
	}
}
