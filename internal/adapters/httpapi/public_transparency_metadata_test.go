package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type transparencyMetadataHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *transparencyMetadataHTTPFake) AuthorizeCreatePublicTransparencyLog(context.Context, identitydomain.Actor, e.PublicTransparencyLogInput) error {
	f.guards++
	return f.guardErr
}
func (f *transparencyMetadataHTTPFake) AuthorizePublishPublicTransparencyLogEntry(context.Context, identitydomain.Actor, e.PublicTransparencyPublicationInput) error {
	f.guards++
	return f.guardErr
}
func (f *transparencyMetadataHTTPFake) CreatePublicTransparencyLog(_ context.Context, a identitydomain.Actor, in e.PublicTransparencyLogInput) (d.PublicTransparencyLog, error) {
	f.calls++
	v, err := e.BuildPublicTransparencyLog("log", a.TenantID, in, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		return v, err
	}
	return v, f.runErr
}
func (f *transparencyMetadataHTTPFake) PublishPublicTransparencyLogEntry(_ context.Context, a identitydomain.Actor, in e.PublicTransparencyPublicationInput) (d.PublicTransparencyLogEntry, error) {
	f.calls++
	v, err := e.BuildPublicTransparencyPublication("entry", a.TenantID, in, e.PublicTransparencyPublicationSource{TenantID: a.TenantID, LogID: in.LogID, CheckpointID: in.CheckpointID, BatchID: "batch", RootHash: "sha256:" + strings.Repeat("A", 64)}, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		return v, err
	}
	return v, f.runErr
}
func TestPublicTransparencyMetadataHTTPFocusedContractsAndPrivateFailures(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	f := &transparencyMetadataHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyMetadataCommands: f}); err == nil {
		t.Fatal("metadata bypasses durable replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyMetadataCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, body, key, state string }{
		{"/v1/public-transparency-logs", `{"name":"public","endpoint":"https://log.example.test","public_key":"pub"}`, "name", "configured"},
		{"/v1/public-transparency-log-entries", `{"log_id":"log","checkpoint_id":"checkpoint","external_id":"external"}`, "log_id", "published"},
	} {
		f.guardErr, f.runErr = nil, nil
		before := f.guards + f.calls
		nullBody := strings.Replace(strings.Replace(tc.body, `"name":"public"`, `"name":null`, 1), `"log_id":"log"`, `"log_id":null`, 1)
		postRaw(t, s, secret, tc.path, "null-field", []byte(nullBody), 400)
		for i, bad := range []string{`null`, `[]`, `{}`, strings.Replace(tc.body, `"`+tc.key+`"`, `"`+strings.ToUpper(tc.key)+`"`, 1), strings.TrimSuffix(tc.body, "}") + `,"` + tc.key + `":"duplicate"}`, strings.TrimSuffix(tc.body, "}") + `,"unknown":true}`, tc.body + ` {}`, strings.Replace(tc.body, `"`+tc.key+`":`, `"`+tc.key+`":null,"ignored":`, 1), strings.Replace(tc.body, tc.key+`":"`, tc.key+`":"x\u0000`, 1), strings.Replace(tc.body, tc.key+`":"`, tc.key+`":"`+string([]byte{255}), 1), strings.Replace(tc.body, tc.key+`":"`, tc.key+`":"`+strings.Repeat("x", 1025), 1)} {
			postRaw(t, s, secret, tc.path, fmt.Sprint(i), []byte(bad), 400)
		}
		out := postRaw(t, s, secret, tc.path, "size", []byte(strings.Repeat(" ", 128<<10)+tc.body), 400)
		if !strings.Contains(out, `"code":"invalid_size"`) || f.guards+f.calls != before {
			t.Fatal("invalid input reached metadata commands", out)
		}
		postRaw(t, s, "", tc.path, "unauth", []byte(tc.body), 401)
		out = postRaw(t, s, secret, tc.path, "valid", []byte(tc.body), 201)
		if !strings.Contains(out, `"state":"`+tc.state+`"`) || strings.Contains(out, "TenantID") || strings.Contains(out, "inclusion_verified") {
			t.Fatal("metadata response changed", out)
		}
		for i, ec := range []struct {
			err    error
			status int
		}{{e.ErrValidation, 400}, {e.ErrNotFound, 404}, {e.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private transparency SQL"), 500}} {
			for _, phase := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				if phase == "guard" {
					f.guardErr = ec.err
				} else {
					f.runErr = ec.err
				}
				before := f.calls
				out := postRaw(t, s, secret, tc.path, fmt.Sprintf("%s-%d", phase, i), []byte(tc.body), ec.status)
				if strings.Contains(out, "private transparency SQL") || strings.Contains(out, `"state":"`+tc.state+`"`) || phase == "guard" && before != f.calls {
					t.Fatal("error exposed internals or success", out)
				}
			}
		}
	}
}
func TestPublicTransparencyMetadataHTTPLocalReplayRequiresCurrentTenantGrant(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	log, err := base.ledger.CreatePublicTransparencyLog(t.Context(), a, app.CreatePublicTransparencyLogInput{Name: "fixture", Endpoint: "https://log.example.test", PublicKey: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := base.ledger.CreateMerkleBatch(t.Context(), a, app.CreateMerkleBatchInput{})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := base.ledger.CreateTransparencyCheckpoint(t.Context(), a, app.CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "internal", ExternalID: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"keys:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, body string }{{"/v1/public-transparency-logs", `{"name":"public","endpoint":"https://log.example.test","public_key":"pub"}`}, {"/v1/public-transparency-log-entries", fmt.Sprintf(`{"log_id":%q,"checkpoint_id":%q,"external_id":"external"}`, log.ID, checkpoint.ID)}} {
		auth.actor.ResourceGrants[0].ResourceType, auth.actor.ResourceGrants[0].ResourceID = "tenant", a.TenantID
		postRaw(t, s, secret, tc.path, "replay", []byte(tc.body), 201)
		postRaw(t, s, secret, tc.path, "replay", []byte(tc.body), 201)
		auth.actor.ResourceGrants[0].ResourceType, auth.actor.ResourceGrants[0].ResourceID = "product", "product"
		postRaw(t, s, secret, tc.path, "replay", []byte(tc.body), 403)
		postRaw(t, s, secret, tc.path, "new", []byte(tc.body), 403)
	}
}
func TestPublicTransparencyMetadataHTTPCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret, _ := marketplaceHTTPFixture(t)
	for _, path := range []string{"/v1/public-transparency-logs", "/v1/public-transparency-log-entries"} {
		body := `{"name":"public","endpoint":"https://log.example.test","public_key":"pub"}`
		if strings.HasSuffix(path, "entries") {
			body = `{"log_id":"log","checkpoint_id":"checkpoint","external_id":"external"}`
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PublicTransparencyMetadataCommands: &transparencyMetadataHTTPFake{}, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://api.example.test"+path, strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", fmt.Sprint(bearer))
			want := 403
			if bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
				want = 201
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("cookie/bearer policy changed", path, bearer, w.Code, w.Body.String())
			}
		}
	}
}

func TestPublicTransparencyMetadataHTTPCreateSchemasBoundInputsOnly(t *testing.T) {
	s, _, _ := marketplaceHTTPFixture(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		schema string
		fields map[string]int
	}{{"CreatePublicTransparencyLogRequest", map[string]int{"name": 256, "endpoint": 4096, "public_key": 16384}}, {"PublishPublicTransparencyLogEntryRequest", map[string]int{"log_id": 1024, "checkpoint_id": 1024, "external_id": 1024}}} {
		schema := doc.Components.Schemas[tc.schema]
		if len(schema.Required) != 3 {
			t.Fatal("required metadata changed", tc.schema)
		}
		for field, max := range tc.fields {
			p := schema.Properties[field]
			if p["maxLength"] != float64(max) || p["minLength"] != float64(1) || !strings.Contains(fmt.Sprint(p["description"]), "UTF-8") {
				t.Fatal("schema lacks raw input bounds", tc.schema, field, p)
			}
		}
	}
	if doc.Components.Schemas["PublicTransparencyLog"].Properties["name"]["maxLength"] != nil {
		t.Fatal("new limits restrict historical metadata")
	}
}
