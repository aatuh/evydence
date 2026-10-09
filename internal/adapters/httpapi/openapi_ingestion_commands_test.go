package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type openAPIIngestionHTTPFake struct {
	guardErr, runErr error
	commands, guards int
	source           evidenceapp.PayloadSource
	input            evidenceapp.OpenAPIIngestionInput
}

func (f *openAPIIngestionHTTPFake) AuthorizeUploadOpenAPIContract(context.Context, identitydomain.Actor, evidenceapp.OpenAPIIngestionInput) error {
	f.guards++
	return f.guardErr
}

func (f *openAPIIngestionHTTPFake) UploadOpenAPIContractPayload(_ context.Context, actor identitydomain.Actor, in evidenceapp.OpenAPIIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.OpenAPIContract, error) {
	f.commands++
	f.source, f.input = source, in
	return evidencedomain.OpenAPIContract{ID: "contract", TenantID: actor.TenantID, ProductID: strings.TrimSpace(in.ProductID), ReleaseID: strings.TrimSpace(in.ReleaseID), Version: strings.TrimSpace(in.Version), Hash: source.Digest}, f.runErr
}

type openAPIStreamedHTTPExecutorFake struct {
	decisionHTTPExecutorFake
	streams int
}

func (f *openAPIStreamedHTTPExecutorFake) WithBodyDigest(ctx context.Context, _ domain.Actor, _, _, _, _ string, guard func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	f.streams++
	if err := guard(ctx); err != nil {
		return 0, nil, err
	}
	return run(ctx)
}

func TestOpenAPIIngestionHTTPRequiresStreamedExecutorAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &openAPIIngestionHTTPFake{}
	for _, executor := range []DurableCommandExecutor{nil, &decisionHTTPExecutorFake{}} {
		if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{OpenAPIIngestionCommands: f, DurableCommandExecutor: executor}); err == nil {
			t.Fatal("focused ingestion fell back to Ledger streamed idempotency")
		}
	}
	executor := &openAPIStreamedHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{OpenAPIIngestionCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"product_id":"product","release_id":"release","version":"1","spec":{}}`)
	postRaw(t, s, "", "/v1/openapi-contracts", "unauth", body, 401)
	if f.commands+f.guards+executor.calls+executor.streams != 0 {
		t.Fatal("unauthenticated effects")
	}
	for _, point := range []string{"authorize", "command"} {
		for i, tc := range []struct {
			err    error
			status int
		}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private parser SQL path"), 500}} {
			f.guardErr, f.runErr = nil, nil
			injected := fmt.Errorf("private command boundary: %w", tc.err)
			if point == "authorize" {
				f.guardErr = injected
			} else {
				f.runErr = injected
			}
			b := postRaw(t, s, secret, "/v1/openapi-contracts", fmt.Sprintf("%s-%d", point, i), body, tc.status)
			if strings.Contains(b, "private") || strings.Contains(b, "boundary") {
				t.Fatal("internal error disclosed", b)
			}
		}
	}
}

func TestOpenAPIIngestionNativeHTTPBoundsHeadersAndCleansSpool(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	base, secret := testServer(t)
	f := &openAPIIngestionHTTPFake{}
	executor := &openAPIStreamedHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{OpenAPIIngestionCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	request := func(reader io.Reader, modify func(*http.Request), want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/openapi-contracts", reader)
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Idempotency-Key", "native")
		r.Header.Set("Content-Type", evidenceapp.OpenAPIMediaType)
		r.Header.Set("X-Evydence-Product-ID", "product")
		r.Header.Set("X-Evydence-Release-ID", "release")
		r.Header.Set("X-Evydence-Version", "1")
		if modify != nil {
			modify(r)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("got %d want %d: %s", w.Code, want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private") {
			t.Fatal("internal streamed error exposed", w.Body.String())
		}
		entries, err := os.ReadDir(temp)
		if err != nil || len(entries) != 0 {
			t.Fatal("request left spool files", entries, err)
		}
	}
	request(strings.NewReader(`{}`), func(r *http.Request) { r.Header.Del("Authorization") }, 401)
	for _, header := range []string{"X-Evydence-Product-ID", "X-Evydence-Release-ID", "X-Evydence-Version"} {
		request(strings.NewReader(`{}`), func(r *http.Request) { r.Header.Del(header) }, 400)
		request(strings.NewReader(`{}`), func(r *http.Request) { r.Header.Add(header, "duplicate") }, 400)
		request(strings.NewReader(`{}`), func(r *http.Request) { r.Header.Set(header, " ") }, 400)
	}
	request(strings.NewReader(""), nil, 400)
	oversized := &repeatingByteReader{remaining: evidenceapp.EvidenceDocumentLimit + 1, value: 'x'}
	request(io.NopCloser(oversized), nil, 400)
	if f.guards+f.commands+executor.streams != 0 {
		t.Fatal("invalid transport reached commands")
	}
	body := strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1) + `{}`
	request(strings.NewReader(body), nil, 201)
	if f.guards != 1 || f.commands != 1 || executor.streams != 1 || f.source.Size != int64(len(body)) || f.source.Digest != evidenceapp.BytesPayloadSource([]byte(body)).Digest || f.input.ProductID != "product" {
		t.Fatal("native upload did not use bounded source", f, executor)
	}
	if reader, err := f.source.Open(); err == nil {
		reader.Close()
		t.Fatal("temporary payload retained after response")
	}
	f.guardErr = evidenceapp.ErrForbidden
	request(strings.NewReader(`{}`), nil, 403)
	if f.commands != 1 {
		t.Fatal("denied source parsed")
	}
	f.guardErr, f.runErr = nil, fmt.Errorf("private parser filesystem path")
	request(strings.NewReader(`{}`), nil, 500)
}

func TestOpenAPIReplayRequiresExactOriginalCoordinates(t *testing.T) {
	a := domain.Actor{TenantID: "tenant"}
	in := evidenceapp.OpenAPIIngestionInput{ProductID: " product ", ReleaseID: " release ", Version: " 1 "}
	digest := evidenceapp.BytesPayloadSource([]byte(`{}`)).Digest
	v := domain.OpenAPIContract{TenantID: "tenant", ProductID: "product", ReleaseID: "release", Version: "1", Hash: digest}
	if !openAPIReplayMatches(v, a, in, digest) {
		t.Fatal("original typed receipt rejected")
	}
	for _, field := range []string{"tenant_id", "product_id", "release_id", "version", "hash"} {
		m := map[string]any{"tenant_id": "tenant", "product_id": "product", "release_id": "release", "version": "1", "hash": digest}
		if !openAPIReplayMatches(m, a, in, digest) {
			t.Fatal("original durable receipt rejected")
		}
		m[field] = "changed"
		if openAPIReplayMatches(m, a, in, digest) {
			t.Fatal("mismatched replay accepted", field)
		}
		delete(m, field)
		if openAPIReplayMatches(m, a, in, digest) {
			t.Fatal("incomplete replay accepted", field)
		}
	}
	if openAPIReplayMatches(nil, a, in, digest) {
		t.Fatal("untyped receipt accepted")
	}
}
