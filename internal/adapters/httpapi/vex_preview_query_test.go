package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type vexPreviewHTTPFake struct {
	calls int
	in    evidencequery.VEXPreviewInput
	err   error
}

func TestVEXPreviewOpenAPIDocumentsFocusedReadOnlyBounds(t *testing.T) {
	server, _ := testServer(t)
	raw, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Description string `json:"description"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/vex/preview", "/v1/vex/cyclonedx/preview"} {
		for _, text := range []string{"PostgreSQL", "current", "artifact", "4096", "8 MiB", "64 KiB", "snapshot", "advisory", "Idempotency-Key"} {
			if !strings.Contains(spec.Paths[path]["post"].Description, text) {
				t.Errorf("%s omits %q", path, text)
			}
		}
	}
}

func (f *vexPreviewHTTPFake) PreviewVEXImport(_ context.Context, a identitydomain.Actor, in evidencequery.VEXPreviewInput) (evidencedomain.VEXImportPreview, error) {
	f.calls++
	f.in = in
	return evidencedomain.VEXImportPreview{TenantID: a.TenantID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Format: in.Format, Advisory: true, DecisionsWouldCreate: 1}, f.err
}

func TestVEXPreviewHTTPUsesFocusedQueryWithoutIdempotencyAndRejectsMalformedEnvelopes(t *testing.T) {
	base, secret := testServer(t)
	f := &vexPreviewHTTPFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{VEXPreviewQuery: f})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"release_id":"release","artifact_id":"artifact","payload":{}}`)
	for _, tc := range []struct{ path, format string }{{"/v1/vex/preview", "openvex"}, {"/v1/vex/cyclonedx/preview", "cyclonedx"}} {
		before := f.calls
		postRaw(t, s, "", tc.path, "", body, 401)
		for _, bad := range []string{`null`, `[]`, `{} {}`, `{"release_id":null,"payload":{}}`, `{"release_id":"release","artifact_id":null,"payload":{}}`, `{"release_id":"release","payload":null}`, `{"release_id":"release","release_id":"other","payload":{}}`, `{"release_id":"release","payload":{},"unknown":true}`, strings.Repeat(" ", 65537) + string(body)} {
			postRaw(t, s, secret, tc.path, "", []byte(bad), 400)
		}
		if f.calls != before {
			t.Fatal("invalid preview reached query")
		}
		for i := 0; i < 2; i++ {
			postRaw(t, s, secret, tc.path, "", body, 200)
		}
		if f.calls != before+2 || f.in.Format != tc.format || f.in.ReleaseID != "release" || f.in.ArtifactID != "artifact" || string(f.in.Payload) != `{}` {
			t.Fatal("preview used replay or changed input", f)
		}
		for i, ec := range []struct {
			err    error
			status int
		}{{evidencequery.ErrValidation, 400}, {evidencequery.ErrNotFound, 404}, {evidencequery.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private preview SQL"), 500}} {
			f.err = ec.err
			if response := postRaw(t, s, secret, tc.path, fmt.Sprintf("unused-%d", i), body, ec.status); strings.Contains(response, "private") {
				t.Fatal("preview leaked internal error", response)
			}
		}
		f.err = nil
	}
}
