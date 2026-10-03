package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type summaryHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func TestSummaryOpenAPIDeclaresOptionalBoundedSelection(t *testing.T) {
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
	req := asStringAnyMap(t, schemas["CreateEvidenceSummaryRequest"])
	if !reflect.DeepEqual(req["required"], []any{"subject_type", "subject_id"}) {
		t.Fatal("automatic selection not optional", req["required"])
	}
	props := asStringAnyMap(t, req["properties"])
	ids := asStringAnyMap(t, props["evidence_ids"])
	if ids["maxItems"] != float64(512) || ids["uniqueItems"] != true || asStringAnyMap(t, ids["items"])["maxLength"] != float64(1024) {
		t.Fatal("missing selection bounds", ids)
	}
	if len(asStringAnyMap(t, props["subject_type"])["enum"].([]any)) != 6 {
		t.Fatal("missing root types")
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/evidence-summaries", "post")
	for _, text := range []string{"512", "4 MiB", "same transaction", "same-host HTTPS Origin", "stored product/project/release"} {
		if !strings.Contains(op["description"].(string), text) {
			t.Fatal("missing summary boundary", text)
		}
	}
}

func (f *summaryHTTPFake) AuthorizeCreateEvidenceSummary(context.Context, identitydomain.Actor, packageapp.CreateEvidenceSummaryInput) error {
	f.guards++
	return f.guardErr
}
func (f *summaryHTTPFake) CreateEvidenceSummary(_ context.Context, a identitydomain.Actor, in packageapp.CreateEvidenceSummaryInput) (packagedomain.EvidenceSummary, error) {
	f.calls++
	return packagedomain.EvidenceSummary{ID: "summary", TenantID: a.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, EvidenceIDs: []string{"evidence"}, Citations: []packagedomain.EvidenceCitation{{EvidenceID: "evidence", CanonicalHash: "hash"}}, SchemaVersion: packagedomain.EvidenceSummaryVersion}, f.runErr
}
func TestSummaryHTTPUsesFocusedPortStrictJSONAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &summaryHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{EvidenceSummaryCommands: f}); err == nil {
		t.Fatal("summary port lacks atomic replay executor")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{EvidenceSummaryCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/evidence-summaries"
	const body = `{"subject_type":"release","subject_id":"release"}`
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"extra":true}`, `{"subject_type":null}`, `{"subject_id":null}`, `{"evidence_ids":null}`, `{"evidence_ids":[null]}`, `{"subject_type":"release","subject_id":"a","subject_id":"b"}`, `{"subject_id":"` + string([]byte{0xff}) + `"}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("invalid JSON reached summary command")
	}
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || !strings.Contains(out, `"evidence_ids"`) || !strings.Contains(out, `"canonical_hash"`) || strings.Contains(out, `"SubjectID"`) {
		t.Fatal("focused summary DTO dispatch", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private summary SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", phase, i), []byte(body), ec.status)
			if strings.Contains(out, "private summary SQL") || strings.Contains(out, `"summary"`) || phase == "guard" && f.calls != before {
				t.Fatal("summary error leaked data", out)
			}
		}
	}
}
func TestSummaryHTTPCookieMutationRequiresSameHTTPSOrigin(t *testing.T) {
	base, secret := testServer(t)
	f := &summaryHTTPFake{}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{EvidenceSummaryCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct {
		origin string
		bearer bool
		status int
	}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://example.com", false, 403}, {"https://example.com", false, 201}, {"https://attacker.example", true, 201}} {
		r := httptest.NewRequest("POST", "https://example.com/v1/evidence-summaries", strings.NewReader(`{"subject_type":"release","subject_id":"release"}`))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
		r.Header.Set("Idempotency-Key", "origin")
		if variant.origin != "" {
			r.Header.Set("Origin", variant.origin)
		}
		if variant.bearer {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		before := f.calls + f.guards
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != variant.status || w.Header().Get("Set-Cookie") != "" || variant.status == 403 && before != f.calls+f.guards {
			t.Fatal("unsafe summary cookie request", w.Code)
		}
	}
}
