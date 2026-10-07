package httpapi

import (
	"context"
	"encoding/json"
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

type vexIngestionHTTPFake struct {
	guardErr, runErr error
	guards, calls    int
	input            evidenceapp.VEXIngestionInput
	source           evidenceapp.PayloadSource
}

func (f *vexIngestionHTTPFake) AuthorizeUploadVEX(_ context.Context, _ identitydomain.Actor, in evidenceapp.VEXIngestionInput) error {
	f.guards++
	f.input = in
	return f.guardErr
}
func (f *vexIngestionHTTPFake) UploadVEXPayload(_ context.Context, a identitydomain.Actor, in evidenceapp.VEXIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.VEXDocument, error) {
	f.calls++
	f.input, f.source = in, source
	return evidencedomain.VEXDocument{ID: "vex", TenantID: a.TenantID, ReleaseID: strings.TrimSpace(in.ReleaseID), ArtifactID: strings.TrimSpace(in.ArtifactID), Format: in.Format}, f.runErr
}

func TestVEXIngestionHTTPUsesFocusedCommandsAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &vexIngestionHTTPFake{}
	for _, executor := range []DurableCommandExecutor{nil, &decisionHTTPExecutorFake{}} {
		if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{VEXIngestionCommands: f, DurableCommandExecutor: executor}); err == nil {
			t.Fatal("VEX ingestion retained Ledger idempotency")
		}
	}
	executor := &openAPIStreamedHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{VEXIngestionCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"release_id":"release","artifact_id":"artifact","payload":{}}`)
	for _, tc := range []struct{ path, format string }{{"/v1/vex", "openvex"}, {"/v1/vex/cyclonedx", "cyclonedx"}} {
		before := f.guards + f.calls
		executorCalls := executor.calls
		postRaw(t, s, "", tc.path, "unauth", body, 401)
		if f.guards+f.calls != before || executor.calls != executorCalls {
			t.Fatal("unauthenticated VEX reached the durable boundary")
		}
		badBodies := []string{`null`, `[]`, `{} {}`, `{"release_id":null,"payload":{}}`, `{"release_id":"release","artifact_id":null,"payload":{}}`, `{"release_id":"release","payload":null}`, `{"release_id":"release","release_id":"other","payload":{}}`, `{"release_id":"release","payload":{},"unknown":true}`}
		for i, bad := range badBodies {
			postRaw(t, s, secret, tc.path, fmt.Sprintf("invalid-%d", i), []byte(bad), 400)
		}
		// The shared durable boundary invokes the decoding guard before any
		// reservation or command. Malformed bodies must never reach VEX ports.
		if f.guards+f.calls != before || executor.calls != executorCalls+len(badBodies) {
			t.Fatal("invalid envelope reached VEX command")
		}
		postRaw(t, s, secret, tc.path, "valid", body, 201)
		if f.input.Format != tc.format || f.source.Size != 2 || f.source.Digest != evidenceapp.BytesPayloadSource([]byte(`{}`)).Digest {
			t.Fatal("VEX route changed format/source", f)
		}
		for i, ec := range []struct {
			err    error
			status int
		}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private VEX SQL"), 500}} {
			for _, phase := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				if phase == "guard" {
					f.guardErr = ec.err
				} else {
					f.runErr = ec.err
				}
				calls := f.calls
				response := postRaw(t, s, secret, tc.path, fmt.Sprintf("%s-%d", phase, i), body, ec.status)
				if strings.Contains(response, "private") || phase == "guard" && f.calls != calls {
					t.Fatal("VEX denial leaked error or normalized", response)
				}
			}
		}
		f.guardErr, f.runErr = nil, nil
	}
}

func TestVEXIngestionNativeHTTPBoundsHeadersAndCleansSpool(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	base, secret := testServer(t)
	f := &vexIngestionHTTPFake{}
	executor := &openAPIStreamedHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{VEXIngestionCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	request := func(reader io.Reader, authenticated bool, modify func(*http.Request), want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/vex", reader)
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		r.Header.Set("Content-Type", evidenceapp.OpenVEXMediaType)
		r.Header.Set("Idempotency-Key", "native-vex")
		r.Header.Set("X-Evydence-Release-ID", "release")
		if modify != nil {
			modify(r)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || strings.Contains(w.Body.String(), "private") {
			t.Fatal(w.Code, w.Body.String())
		}
		entries, err := os.ReadDir(temp)
		if err != nil || len(entries) != 0 {
			t.Fatal("VEX retained spool files", entries, err)
		}
	}
	request(strings.NewReader(`{}`), false, nil, 401)
	request(strings.NewReader(""), true, nil, 400)
	request(&repeatingByteReader{remaining: evidenceapp.EvidenceDocumentLimit + 1, value: 'x'}, true, nil, 400)
	request(strings.NewReader(`{}`), true, func(r *http.Request) { r.Header.Del("X-Evydence-Release-ID") }, 400)
	for _, header := range []string{"X-Evydence-Release-ID", "X-Evydence-Artifact-ID"} {
		request(strings.NewReader(`{}`), true, func(r *http.Request) { r.Header.Add(header, "first"); r.Header.Add(header, "second") }, 400)
	}
	if f.calls+f.guards+executor.streams != 0 {
		t.Fatal("invalid native VEX reached command")
	}
	body := strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1) + `{}`
	request(strings.NewReader(body), true, nil, 201)
	if f.calls != 1 || f.guards != 1 || executor.streams != 1 || f.input.Format != "openvex" || f.source.Size != int64(len(body)) {
		t.Fatal("native VEX source changed", f)
	}
	if reader, err := f.source.Open(); err == nil {
		reader.Close()
		t.Fatal("native VEX source outlived request")
	}
	f.guardErr = application.ErrForbidden
	request(strings.NewReader(`{}`), true, nil, 403)
	if f.calls != 1 {
		t.Fatal("denied VEX normalized")
	}
}

func TestVEXNativeReplayRequiresOriginalCoordinates(t *testing.T) {
	a := domain.Actor{TenantID: "tenant"}
	in := evidenceapp.VEXIngestionInput{ReleaseID: " release ", ArtifactID: " artifact ", Format: "openvex"}
	if !vexReplayMatches(domain.VEXDocument{TenantID: "tenant", ReleaseID: "release", ArtifactID: "artifact", Format: "openvex"}, a, in) {
		t.Fatal("typed receipt rejected")
	}
	for _, field := range []string{"tenant_id", "release_id", "artifact_id", "format"} {
		m := map[string]any{"tenant_id": "tenant", "release_id": "release", "artifact_id": "artifact", "format": "openvex"}
		if !vexReplayMatches(m, a, in) {
			t.Fatal("durable receipt rejected")
		}
		m[field] = "changed"
		if vexReplayMatches(m, a, in) {
			t.Fatal("foreign receipt accepted", field)
		}
		delete(m, field)
		if vexReplayMatches(m, a, in) {
			t.Fatal("incomplete receipt accepted", field)
		}
	}
	in.ArtifactID = ""
	if !vexReplayMatches(map[string]any{"tenant_id": "tenant", "release_id": "release", "format": "openvex"}, a, in) {
		t.Fatal("optional artifact omission changed")
	}
	if vexReplayMatches(nil, a, in) {
		t.Fatal("untyped receipt accepted")
	}
}

func TestVEXIngestionOpenAPIDocumentsFocusedPostgresContract(t *testing.T) {
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
	for _, path := range []string{"/v1/vex", "/v1/vex/cyclonedx"} {
		for _, text := range []string{"PostgreSQL", "1024", "100,000", "1 MiB", "20 MiB", "body-only", "accepted", "post-commit", "current", "authority"} {
			if !strings.Contains(spec.Paths[path]["post"].Description, text) {
				t.Errorf("%s contract omits %q", path, text)
			}
		}
	}
}
