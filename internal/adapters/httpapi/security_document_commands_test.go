package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type securityDocumentHTTPFake struct {
	guards, calls    int
	scan             evidenceapp.UploadSecurityScanInput
	manual           evidenceapp.UploadManualSecurityDocumentInput
	guardErr, runErr error
}

func (f *securityDocumentHTTPFake) AuthorizeUploadSecurityScan(_ context.Context, _ identitydomain.Actor, in evidenceapp.UploadSecurityScanInput) error {
	f.guards++
	f.scan = in
	return f.guardErr
}
func (f *securityDocumentHTTPFake) AuthorizeUploadManualSecurityDocument(_ context.Context, _ identitydomain.Actor, in evidenceapp.UploadManualSecurityDocumentInput) error {
	f.guards++
	f.manual = in
	return f.guardErr
}
func (f *securityDocumentHTTPFake) UploadSecurityScan(_ context.Context, a identitydomain.Actor, in evidenceapp.UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	f.calls++
	f.scan = in
	return evidencedomain.SecurityScan{ID: "scan", TenantID: a.TenantID, Category: in.Category, Summary: map[string]int{"high": 1}}, f.runErr
}
func (f *securityDocumentHTTPFake) UploadManualSecurityDocument(_ context.Context, a identitydomain.Actor, in evidenceapp.UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error) {
	f.calls++
	f.manual = in
	return evidencedomain.ManualSecurityDocument{ID: "doc", TenantID: a.TenantID, Title: in.Title}, f.runErr
}

func TestSecurityDocumentHTTPUsesFocusedCommandsAndRejectsInvalidEnvelopes(t *testing.T) {
	base, secret := testServer(t)
	f := &securityDocumentHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{SecurityDocumentCommands: f}); err == nil {
		t.Fatal("security documents retained Ledger idempotency")
	}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{SecurityDocumentCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, body string }{
		{"/v1/security-scans", `{"product_id":"product","release_id":"release","artifact_id":"artifact","category":"secret_scan","scanner":"scanner","target_ref":"target","payload":{}}`},
		{"/v1/api-security-scans", `{"product_id":"product","release_id":"release","artifact_id":"artifact","scanner":"scanner","target_ref":"target","payload":{}}`},
		{"/v1/security-documents", `{"product_id":"product","release_id":"release","document_type":"security_review","title":"Review","sensitivity":"restricted","payload":{}}`},
	} {
		before := f.guards + f.calls
		postRaw(t, s, "", tc.path, "unauth", []byte(tc.body), 401)
		for i, bad := range []string{`null`, `[]`, `{} {}`, strings.Replace(tc.body, `"product_id":"product"`, `"product_id":null`, 1), strings.Replace(tc.body, `"payload":{}`, `"payload":null`, 1), strings.Replace(tc.body, `"product_id":"product"`, `"product_id":"product","product_id":"other"`, 1), strings.Replace(tc.body, `"payload":{}`, `"payload":{},"unknown":true`, 1), strings.Repeat(" ", 65537) + tc.body} {
			postRaw(t, s, secret, tc.path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
		}
		if f.guards+f.calls != before {
			t.Fatal("malformed body reached command")
		}
		fields := []string{"product_id", "release_id", "payload"}
		if tc.path == "/v1/security-documents" {
			fields = append(fields, "document_type", "title", "sensitivity", "media_type")
		} else {
			fields = append(fields, "artifact_id", "format", "scanner", "target_ref")
			if tc.path == "/v1/security-scans" {
				fields = append(fields, "category")
			}
		}
		for _, field := range fields {
			var body map[string]any
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatal(err)
			}
			body[field] = nil
			invalid, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			postRaw(t, s, secret, tc.path, "null-"+field, invalid, 400)
		}
		if f.guards+f.calls != before {
			t.Fatal("null metadata reached command")
		}
		postRaw(t, s, secret, tc.path, "valid", []byte(tc.body), 201)
		if tc.path == "/v1/api-security-scans" && f.scan.Category != "api_security" {
			t.Fatal("API category changed", f.scan)
		}
		for i, ec := range []struct {
			err    error
			status int
		}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private security SQL"), 500}} {
			for _, phase := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				if phase == "guard" {
					f.guardErr = ec.err
				} else {
					f.runErr = ec.err
				}
				calls := f.calls
				out := postRaw(t, s, secret, tc.path, fmt.Sprintf("%s-%d", phase, i), []byte(tc.body), ec.status)
				if strings.Contains(out, "private") || phase == "guard" && f.calls != calls {
					t.Fatal("unsafe denial", out)
				}
			}
		}
		f.guardErr, f.runErr = nil, nil
		if tc.path == "/v1/security-documents" {
			for i, payload := range []string{`"encoded text"`, `17`, `true`, `[]`, `{"nested":null}`} {
				body := strings.Replace(tc.body, `"payload":{}`, `"payload":`+payload, 1)
				postRaw(t, s, secret, tc.path, fmt.Sprintf("opaque-%d", i), []byte(body), 201)
				if string(f.manual.Raw) != payload {
					t.Fatal("opaque document bytes were decoded or rewritten", string(f.manual.Raw), payload)
				}
			}
		}
	}
}
