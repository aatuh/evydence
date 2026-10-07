package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidenceCreationHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	actor    identitydomain.Actor
	input    evidenceapp.CreateEvidenceInput
	err      error
}

func (f *evidenceCreationHTTPFake) AuthorizeEvidenceCreation(context.Context, identitydomain.Actor, evidenceapp.CreateEvidenceInput) error {
	f.guards++
	return f.guardErr
}

func TestEvidenceCreationRequiresNativeReplayAndCurrentAuthority(t *testing.T) {
	base, secret := testServer(t)
	f := &evidenceCreationHTTPFake{}
	if s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceCreationCommands: f}); err == nil || s != nil {
		t.Error("generic evidence accepted aggregate replay")
	}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceCreationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.evidenceIngestion = nil, nil
	body := []byte(`{"type":"manual","title":"Evidence","payload_hash":"sha256:` + strings.Repeat("a", 64) + `"}`)
	one := postRaw(t, s, secret, "/v1/evidence", "original", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/evidence", "original", body, 201))
	f.guardErr = application.ErrForbidden
	postRaw(t, s, secret, "/v1/evidence", "original", body, 403)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("generic evidence replay skipped current authority", f)
	}
}

func (f *evidenceCreationHTTPFake) CreateEvidence(_ context.Context, actor identitydomain.Actor, input evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	f.calls++
	f.actor = actor
	f.input = input
	return evidencedomain.EvidenceItem{ID: "durable-evidence", TenantID: actor.TenantID, Type: input.Type, Title: input.Title, PayloadHash: input.PayloadHash}, f.err
}
func TestEvidenceCreationHTTPMapsCompleteDTOAndSafeErrors(t *testing.T) {
	local, secret := testServer(t)
	fake := &evidenceCreationHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{EvidenceCreationCommands: fake, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	raw := []byte(`{"product_id":"p","project_id":"j","release_id":"r","build_id":"b","deployment_id":"d","type":"manual","subtype":"note","title":"Evidence","source_system":"ci","source_identity":{"job":"one"},"collector_id":"collector","observed_at":"2026-10-02T12:00:00Z","payload_ref":"opaque","payload_hash":"` + digest + `","payload_media_type":"text/plain","payload_size":7,"subject_refs":[{"type":"build","id":"b","digest":""}],"metadata":{"ok":true},"tags":["tag"],"limitations":["record only"]}`)
	body := postRaw(t, server, secret, "/v1/evidence", "creation", raw, 201)
	want := evidenceapp.CreateEvidenceInput{ProductID: "p", ProjectID: "j", ReleaseID: "r", BuildID: "b", DeploymentID: "d", Type: "manual", Subtype: "note", Title: "Evidence", SourceSystem: "ci", SourceIdentity: map[string]any{"job": "one"}, CollectorID: "collector", ObservedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), PayloadRef: "opaque", PayloadHash: digest, PayloadMediaType: "text/plain", PayloadSize: 7, SubjectRefs: []evidencedomain.SubjectRef{{Type: "build", ID: "b"}}, Metadata: map[string]any{"ok": true}, Tags: []string{"tag"}, Limitations: []string{"record only"}}
	if fake.calls != 1 || fake.actor.TenantID == "" || !reflect.DeepEqual(fake.input, want) || !strings.Contains(body, `"id":"durable-evidence"`) {
		t.Fatal("DTO mismatch", fake, body)
	}
	assertTrustHTTPReplay(t, body, postRaw(t, server, secret, "/v1/evidence", "creation", raw, 201))
	if fake.calls != 1 {
		t.Fatal("replay repeated command", fake.calls)
	}
	postRaw(t, server, secret, "/v1/evidence", "creation", append(raw, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private SQL secret"), 500}} {
		fake.err = tc.err
		failure := postRaw(t, server, secret, "/v1/evidence", fmt.Sprintf("failure-%d", i), raw, tc.status)
		if strings.Contains(failure, "private SQL") || strings.Contains(failure, "durable-evidence") {
			t.Fatal("error leaked internals or result", failure)
		}
	}
}
