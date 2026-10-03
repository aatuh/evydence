package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type portalHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
	input            packageapp.CreatePortalAccessInput
}

func (f *portalHTTPFake) AuthorizeCreatePortalAccess(context.Context, identitydomain.Actor, packageapp.CreatePortalAccessInput) error {
	f.guards++
	return f.guardErr
}
func (f *portalHTTPFake) AuthorizeRevokePortalAccess(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}
func (f *portalHTTPFake) CreatePortalAccess(_ context.Context, a identitydomain.Actor, in packageapp.CreatePortalAccessInput) (packagedomain.CustomerPortalAccess, string, error) {
	f.calls++
	f.input = in
	return packagedomain.CustomerPortalAccess{ID: "access", TenantID: a.TenantID, PackageID: in.PackageID, CustomerName: in.CustomerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: in.Watermark, Hash: "private-token-hash", SchemaVersion: packagedomain.CustomerPortalAccessVersion}, "evycp_private-once", f.runErr
}
func (f *portalHTTPFake) RevokePortalAccess(_ context.Context, a identitydomain.Actor, id string) (packagedomain.CustomerPortalAccess, error) {
	f.calls++
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	return packagedomain.CustomerPortalAccess{ID: id, TenantID: a.TenantID, PackageID: "package", RevokedAt: &now, Hash: "private-token-hash"}, f.runErr
}

const portalHTTPBody = `{"package_id":" package ","customer_name":" Customer ","reviewer_email":" PERSON@EXAMPLE.TEST ","require_nda":true,"expires_at":"2027-01-01T12:00:00Z"}`

func TestPortalHTTPStrictInputFocusedProjectionAndSafeFailures(t *testing.T) {
	base, secret := testServer(t)
	f := &portalHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PortalAccessCommands: f}); err == nil {
		t.Fatal("portal writes lack atomic replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PortalAccessCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/customer-portal/access"
	bad := []string{`null`, `[]`, `{}`, `{"package_id":"x","package_id":"y"}`, `{"package_id":"x","PACKAGE_ID":"y"}`, strings.TrimSuffix(portalHTTPBody, "}") + `,"unknown":true}`, portalHTTPBody + ` {}`, strings.Replace(portalHTTPBody, " package ", `package\u0000`, 1), strings.Replace(portalHTTPBody, " Customer ", strings.Repeat("x", 641), 1), strings.Repeat(" ", 65537) + portalHTTPBody, `{"package_id":"` + string([]byte{0xff}) + `"}`}
	for _, field := range []string{"package_id", "customer_name", "reviewer_name", "reviewer_email", "require_nda", "watermark", "expires_at"} {
		bad = append(bad, `{"`+field+`":null}`)
	}
	for i, b := range bad {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(b), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("malformed input reached portal issuer")
	}
	out := postRaw(t, s, secret, path, "create", []byte(portalHTTPBody), 201)
	if f.calls != 1 || f.guards != 1 || f.input.PackageID != "package" || f.input.CustomerName != "Customer" || f.input.ReviewerEmail != "person@example.test" || !strings.Contains(out, `"secret":"evycp_private-once"`) || strings.Contains(out, "private-token-hash") || strings.Contains(out, `"Hash"`) {
		t.Fatal("portal mapping/privacy differs", out)
	}
	out = postRaw(t, s, secret, path+"/access/revoke", "revoke", nil, 200)
	if !strings.Contains(out, `"revoked_at"`) || strings.Contains(out, "private-token-hash") {
		t.Fatal("revocation response differs", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private portal SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(portalHTTPBody), ec.status)
			if strings.Contains(out, "private portal SQL") || strings.Contains(out, "evycp_private-once") || strings.Contains(out, "private-token-hash") || stage == "guard" && before != f.calls {
				t.Fatal("failed portal issuance disclosed material")
			}
		}
	}
}
func TestPortalHTTPCookieMutationsRequireOriginBothProfiles(t *testing.T) {
	base, _ := testServer(t)
	for _, focused := range []bool{false, true} {
		f := &portalHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.PortalAccessCommands = f
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/v1/customer-portal/access", "/v1/customer-portal/access/access/revoke"} {
			r := httptest.NewRequest("POST", "https://api.example.test"+path, strings.NewReader(portalHTTPBody))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid-session"})
			r.Header.Set("Idempotency-Key", "origin")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 403 || f.guards+f.calls != 0 {
				t.Fatal("ambient cookie mutation bypassed origin", focused, path, w.Code)
			}
		}
	}
}

type portalTokenHTTPFake struct {
	calls    int
	download bool
}

func (f *portalTokenHTTPFake) AccessPortalPackage(_ context.Context, _ string, _ packageapp.PortalAcceptanceInput, download bool) (packagedomain.CustomerSecurityPackage, error) {
	f.calls++
	f.download = download
	return packagedomain.CustomerSecurityPackage{ID: "package", Title: "<script>private()</script>", Manifest: map[string]any{}, ManifestHash: "sha256:manifest", DistributionWatermark: "<b>Review</b>"}, nil
}
func TestPortalTokenHTTPRejectsAmbiguousInputBeforeConsumption(t *testing.T) {
	base, _ := testServer(t)
	f := &portalTokenHTTPFake{}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{PortalTokenCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/customer-portal/package", "/v1/customer-portal/package/download"} {
		for _, bad := range []string{`null`, `[]`, `{"token":null}`, `{"token":"a","TOKEN":"b"}`, `{"token":"a","nda_accepted":null}`, `{"token":"a","nda_accepted_by":null}`, `{"token":"a","nda_accepted_by":"` + strings.Repeat("x", 641) + `"}`, `{"token":"` + string([]byte{0xff}) + `"}`} {
			postRaw(t, s, "", path, "", []byte(bad), 400)
		}
	}
	if f.calls != 0 {
		t.Fatal("ambiguous portal input reached credential verification")
	}
	r := httptest.NewRequest("POST", "/v1/customer-portal/package/view", strings.NewReader("token=evycp_explicit_body_secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "evycp_explicit_body_secret") || strings.Contains(w.Body.String(), "<script>private()</script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("focused browser portal lost escaping/privacy headers")
	}
}
