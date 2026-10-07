package httpapi

import (
	"context"
	"encoding/json"
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

type sbomIngestionHTTPFake struct {
	guardErr, runErr error
	calls, guards    int
	input            evidenceapp.SBOMIngestionInput
	source           evidenceapp.PayloadSource
}

func (f *sbomIngestionHTTPFake) AuthorizeUploadSBOM(context.Context, identitydomain.Actor, evidenceapp.SBOMIngestionInput) error {
	f.guards++
	return f.guardErr
}
func (f *sbomIngestionHTTPFake) UploadSBOMPayload(_ context.Context, a identitydomain.Actor, in evidenceapp.SBOMIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.SBOM, error) {
	f.calls++
	f.input, f.source = in, source
	return evidencedomain.SBOM{ID: "sbom", TenantID: a.TenantID, ReleaseID: strings.TrimSpace(in.ReleaseID), ArtifactID: strings.TrimSpace(in.ArtifactID), Format: in.Format}, f.runErr
}
func TestSBOMIngestionHTTPUsesFocusedCommandsAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &sbomIngestionHTTPFake{}
	for _, executor := range []DurableCommandExecutor{nil, &decisionHTTPExecutorFake{}} {
		if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SBOMIngestionCommands: f, DurableCommandExecutor: executor}); err == nil {
			t.Fatal("SBOM ingestion retained Ledger idempotency")
		}
	}
	executor := &openAPIStreamedHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SBOMIngestionCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"release_id":"release","artifact_id":"artifact","payload":{}}`)
	for _, path := range []string{"/v1/sboms", "/v1/sboms/spdx"} {
		postRaw(t, s, "", path, "unauth", body, 401)
	}
	if executor.calls+executor.streams+f.calls+f.guards != 0 {
		t.Fatal("unauthenticated effects")
	}
	for _, tc := range []struct{ path, format, media string }{{"/v1/sboms", "cyclonedx", evidenceapp.CycloneDXMediaType}, {"/v1/sboms/spdx", "spdx", evidenceapp.SPDXMediaType}} {
		postRaw(t, s, secret, tc.path, "valid", body, 201)
		if f.input.Format != tc.format || f.source.Size != 2 {
			t.Fatal("wrong format/source selected", f)
		}
		for i, errCase := range []struct {
			err    error
			status int
		}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {fmt.Errorf("private parser SQL"), 500}} {
			for _, phase := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				injected := fmt.Errorf("private boundary: %w", errCase.err)
				if phase == "guard" {
					f.guardErr = injected
				} else {
					f.runErr = injected
				}
				b := postRaw(t, s, secret, tc.path, fmt.Sprintf("%s-%d", phase, i), body, errCase.status)
				if strings.Contains(b, "private") {
					t.Fatal("internal error disclosed", b)
				}
			}
		}
		f.guardErr, f.runErr = nil, nil
		send := func(modify func(*http.Request), want int) {
			t.Helper()
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1)+`{}`))
			r.Header.Set("Authorization", "Bearer "+secret)
			r.Header.Set("Idempotency-Key", "native")
			r.Header.Set("Content-Type", tc.media)
			r.Header.Set("X-Evydence-Release-ID", "release")
			r.Header.Set("X-Evydence-Artifact-ID", "artifact")
			if modify != nil {
				modify(r)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		send(nil, 201)
		if f.input.Format != tc.format || f.source.Size <= app.SmallJSONRequestLimit {
			t.Fatal("native source was not streamed", f)
		}
		before := f.calls + f.guards
		send(func(r *http.Request) { r.Header.Del("X-Evydence-Release-ID") }, 400)
		for _, header := range []string{"X-Evydence-Release-ID", "X-Evydence-Artifact-ID"} {
			send(func(r *http.Request) { r.Header.Add(header, "duplicate") }, 400)
		}
		if f.calls+f.guards != before {
			t.Fatal("malformed metadata reached commands")
		}
	}
}
func TestSBOMNativeReplayRequiresOriginalResourceCoordinates(t *testing.T) {
	a := domain.Actor{TenantID: "tenant"}
	in := evidenceapp.SBOMIngestionInput{ReleaseID: " release ", ArtifactID: " artifact ", Format: "cyclonedx"}
	if !sbomReplayMatches(domain.SBOM{TenantID: "tenant", ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx"}, a, in) {
		t.Fatal("typed receipt rejected")
	}
	for _, field := range []string{"tenant_id", "release_id", "artifact_id", "format"} {
		m := map[string]any{"tenant_id": "tenant", "release_id": "release", "artifact_id": "artifact", "format": "cyclonedx"}
		if !sbomReplayMatches(m, a, in) {
			t.Fatal("durable receipt rejected")
		}
		m[field] = "changed"
		if sbomReplayMatches(m, a, in) {
			t.Fatal("mismatched replay accepted", field)
		}
	}
	in.ArtifactID = ""
	if !sbomReplayMatches(map[string]any{"tenant_id": "tenant", "release_id": "release", "format": "cyclonedx"}, a, in) {
		t.Fatal("omitted optional artifact rejected")
	}
	if sbomReplayMatches(nil, a, in) {
		t.Fatal("untyped receipt accepted")
	}
}

func TestSBOMIngestionNativeHTTPBoundsAndCleansSpool(t *testing.T) {
	for _, tc := range []struct{ path, format, media string }{{"/v1/sboms", "cyclonedx", evidenceapp.CycloneDXMediaType}, {"/v1/sboms/spdx", "spdx", evidenceapp.SPDXMediaType}} {
		t.Run(tc.format, func(t *testing.T) {
			temp := t.TempDir()
			t.Setenv("TMPDIR", temp)
			base, secret := testServer(t)
			f := &sbomIngestionHTTPFake{}
			executor := &openAPIStreamedHTTPExecutorFake{}
			s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SBOMIngestionCommands: f, DurableCommandExecutor: executor})
			if err != nil {
				t.Fatal(err)
			}
			request := func(reader io.Reader, authenticated bool, want int) {
				t.Helper()
				r := httptest.NewRequest("POST", tc.path, reader)
				if authenticated {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				r.Header.Set("Content-Type", tc.media)
				r.Header.Set("Idempotency-Key", "bounded-native")
				r.Header.Set("X-Evydence-Release-ID", "release")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != want || strings.Contains(w.Body.String(), "private") {
					t.Fatalf("got %d want %d: %s", w.Code, want, w.Body.String())
				}
				entries, err := os.ReadDir(temp)
				if err != nil || len(entries) != 0 {
					t.Fatal("request retained spool files", entries, err)
				}
			}
			request(strings.NewReader(`{}`), false, 401)
			request(strings.NewReader(""), true, 400)
			request(&repeatingByteReader{remaining: evidenceapp.EvidenceDocumentLimit + 1, value: 'x'}, true, 400)
			if f.calls+f.guards+executor.streams != 0 {
				t.Fatal("invalid transport reached command")
			}
			body := strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1) + `{}`
			request(strings.NewReader(body), true, 201)
			if f.calls != 1 || f.guards != 1 || executor.streams != 1 || f.input.Format != tc.format || f.input.ArtifactID != "" || f.source.Size != int64(len(body)) || f.source.Digest != evidenceapp.BytesPayloadSource([]byte(body)).Digest {
				t.Fatal("streamed payload identity changed", f, executor)
			}
			if reader, err := f.source.Open(); err == nil {
				reader.Close()
				t.Fatal("temporary source remains readable after response")
			}
			f.guardErr = application.ErrForbidden
			request(strings.NewReader(`{}`), true, 403)
			if f.calls != 1 {
				t.Fatal("denied source reached ingestion")
			}
			f.guardErr, f.runErr = nil, fmt.Errorf("private source path")
			request(strings.NewReader(`{}`), true, 500)
		})
	}
}

func TestSBOMIngestionOpenAPIDocumentsFocusedPostgresContract(t *testing.T) {
	server, _ := testServer(t)
	data, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Description string `json:"description"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/sboms", "/v1/sboms/spdx"} {
		for _, text := range []string{"PostgreSQL", "1024", "64 KiB", "body-only", "worker-owned", "completeness"} {
			if !strings.Contains(spec.Paths[path]["post"].Description, text) {
				t.Errorf("%s contract omits %q", path, text)
			}
		}
	}
}
