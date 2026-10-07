package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type sourceSnapshotHTTPFake struct {
	guards   int
	guardErr error
	calls    int
	provider string
	input    integrationapp.SourceSnapshotInput
	err      error
}

func (f *sourceSnapshotHTTPFake) AuthorizeSourceSnapshot(context.Context, identitydomain.Actor, string, integrationapp.SourceSnapshotInput) error {
	f.guards++
	return f.guardErr
}

func TestSourceSnapshotHTTPRequiresNativeDurableReplay(t *testing.T) {
	s, _ := testServer(t)
	if v, err := newLegacyServerFixtureWithOptions(s.ledger, ServerOptions{SourceSnapshotCommands: &sourceSnapshotHTTPFake{}}); err == nil || v != nil {
		t.Fatal("snapshot accepted aggregate-backed replay")
	}
}

func TestSourceSnapshotHTTPChecksCurrentGuardBeforeReplay(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		s, secret := testServer(t)
		f := &sourceSnapshotHTTPFake{}
		s.sourceSnapshotCommands = f
		s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		path := "/v1/collectors/" + provider + "/source-snapshots"
		body := []byte(`{"repository":{"full_name":"org/api"}}`)
		one := postRaw(t, s, secret, path, "current", body, 201)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "current", body, 201))
		f.guardErr = application.ErrForbidden
		out := postRaw(t, s, secret, path, "current", body, 403)
		if f.calls != 1 || f.guards != 3 || strings.Contains(out, `"data"`) {
			t.Fatal("snapshot replay ignored current authority", f, out)
		}
	}
}

func (f *sourceSnapshotHTTPFake) RecordSourceSnapshot(_ context.Context, a identitydomain.Actor, provider string, in integrationapp.SourceSnapshotInput) (integrationapp.SourceSnapshotResult, error) {
	f.calls++
	f.provider, f.input = provider, in
	return integrationapp.SourceSnapshotResult{Repository: integrationdomain.SourceRepository{ID: "durable_repo", TenantID: a.TenantID, Provider: provider, FullName: in.Repository.FullName}}, f.err
}
func TestSourceSnapshotHTTPUsesFocusedCommandsAndRejectsMalformedNestedInputs(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			local, secret := testServer(t)
			f := &sourceSnapshotHTTPFake{}
			s, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{SourceSnapshotCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
			if err != nil {
				t.Fatal(err)
			}
			path := "/v1/collectors/" + provider + "/source-snapshots"
			in := map[string]any{"repository": map[string]any{"full_name": "org/not-in-ledger"}, "commit": map[string]any{"sha": strings.Repeat("a", 40), "message": " private message "}}
			body := postJSON(t, s, secret, path, "snapshot-replay", in, 201)
			if !strings.Contains(body, `"id":"durable_repo"`) || strings.Contains(body, "private message") || f.calls != 1 || f.provider != provider || f.input.Commit == nil || f.input.Commit.Message != " private message " {
				t.Fatal(body, f)
			}
			for _, key := range []string{"repository", "commit", "branch", "pull_request"} {
				if !strings.Contains(body, `"`+key+`":`) {
					t.Fatal("missing compatibility result component", body)
				}
			}
			assertTrustHTTPReplay(t, body, postJSON(t, s, secret, path, "snapshot-replay", in, 201))
			if f.calls != 1 {
				t.Fatal("replay ran commands", f)
			}
			postJSON(t, s, secret, path, "snapshot-replay", map[string]any{"repository": map[string]any{"full_name": "changed"}}, 409)
			bad := []string{`null`, `[]`, `{}`, `{"repository":null}`, `{"repository":[]}`, `{"repository":{"full_name":null}}`, `{"repository":{"full_name":"a","full_name":"b"}}`, `{"repository":{"full_name":"a","unknown":true}}`, `{"repository":{"full_name":"a"},"project_id":null}`, `{"repository":{"full_name":"a"},"unknown":true}`, `{"repository":{"full_name":"a"},"commit":null}`, `{"repository":{"full_name":"a"},"commit":{"sha":null}}`, `{"repository":{"full_name":"a"},"commit":{"message":null}}`, `{"repository":{"full_name":"a"},"commit":{"author":null}}`, `{"repository":{"full_name":"a"},"commit":{"committed_at":null}}`, `{"repository":{"full_name":"a"},"commit":{"committed_at":"bad"}}`, `{"repository":{"full_name":"a"},"commit":{"repository_id":"injected"}}`, `{"repository":{"full_name":"a"},"branch":null}`, `{"repository":{"full_name":"a"},"branch":{"protected":null}}`, `{"repository":{"full_name":"a"},"branch":{"protected":"true"}}`, `{"repository":{"full_name":"a"},"branch":{"head_commit_id":"injected"}}`, `{"repository":{"full_name":"a"},"pull_request":null}`, `{"repository":{"full_name":"a"},"pull_request":{"title":null}}`, `{"repository":{"full_name":"a"},"pull_request":{"provider":"injected"}}`, `{} {}`}
			for i, raw := range bad {
				postRaw(t, s, secret, path, fmt.Sprintf("bad-snapshot-%d", i), []byte(raw), 400)
			}
			postRaw(t, s, secret, path, "oversized-snapshot", []byte(strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1)+`{"repository":{"full_name":"a"}}`), 400)
			// Every nested property is non-nullable, including optional metadata.
			for object, fields := range map[string][]string{"repository": {"full_name", "clone_url", "default_branch"}, "commit": {"sha", "author", "message", "committed_at"}, "branch": {"name", "protected", "protection_hash"}, "pull_request": {"provider_id", "title", "state", "source_branch", "target_branch", "review_decision"}} {
				for _, field := range fields {
					raw := fmt.Sprintf(`{"repository":{"full_name":"a"},"%s":{"%s":null}}`, object, field)
					if object == "repository" {
						raw = fmt.Sprintf(`{"repository":{"%s":null}}`, field)
					}
					postRaw(t, s, secret, path, "null-"+object+"-"+field, []byte(raw), 400)
				}
			}
			if f.calls != 1 {
				t.Fatal("malformed request reached command", f.calls)
			}
			for i, tc := range []struct {
				err    error
				status int
			}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {errors.New("private source SQL"), 500}} {
				f.err = tc.err
				body := postJSON(t, s, secret, path, fmt.Sprintf("failed-snapshot-%d", i), in, tc.status)
				if strings.Contains(body, "private source SQL") || strings.Contains(body, "durable_repo") {
					t.Fatal(body)
				}
			}
		})
	}
}
func TestSourceSnapshotOpenAPIMatchesDefaultsAndAtomicity(t *testing.T) {
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
	for _, v := range asStringAnyMap(t, schemas["SourceSnapshotCommitInput"])["required"].([]any) {
		if v == "committed_at" {
			t.Fatal("defaulted commit time required")
		}
	}
	found := false
	for _, v := range asStringAnyMap(t, schemas["SourceSnapshotPullRequestInput"])["required"].([]any) {
		if v == "title" {
			found = true
		}
	}
	if !found {
		t.Fatal("required pull request title omitted")
	}
	for _, provider := range []string{"github", "gitlab"} {
		op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/collectors/"+provider+"/source-snapshots", "post")
		desc, _ := op["description"].(string)
		for _, want := range []string{"one transaction", "ownership", "message hash", "does not verify", "omitted commit time", "native durable replay", "before reservation and completed replay", "Raw nested input", "Origin", "nondurable"} {
			if !strings.Contains(desc, want) {
				t.Fatal("missing snapshot contract", desc)
			}
		}
	}
}
