package httpapi

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestPortalTokenRouteAuthorizationMatrix(t *testing.T) {
	for _, tc := range []struct {
		operation, path, audit string
		form, archive          bool
	}{
		{"accessCustomerPortalPackage", "/v1/customer-portal/package", "customer_portal_package.accessed", false, false},
		{"downloadCustomerPortalPackage", "/v1/customer-portal/package/download", "customer_portal_package.downloaded", false, true},
		{"customerPortalPackageView", "/v1/customer-portal/package/view", "customer_portal_package.accessed", true, false},
		{"downloadCustomerPortalPackageView", "/v1/customer-portal/package/view/download", "customer_portal_package.downloaded", true, true},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			ledger, factory := integrationRegressionLedger()
			owner, foreign := seedPortalFixtureScope(t, ledger, "Owner"), seedPortalFixtureScope(t, ledger, "Foreign")
			ports := portalRegressionPorts(ledger)
			access, token, err := ports.CreatePortalAccess(t.Context(), owner.actor, portalFixtureInput(owner))
			if err != nil {
				t.Fatal(err)
			}
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			s.portalTokenCommands = ports
			// Bearer/tenant-admin authority cannot bypass a package token or
			// replace consent on these public credential-bound operations.
			s.authn = &configuredAuthenticator{actor: domain.Actor{TenantID: owner.actor.TenantID, KeyID: "admin", Scopes: []string{"*", "admin"}}}
			request := func(secret string, accept bool, status int) *httptest.ResponseRecorder {
				t.Helper()
				if tc.form {
					v := url.Values{"token": {secret}}
					if accept {
						v.Set("nda_accepted", "true")
						v.Set("nda_accepted_by", "Reviewer")
					}
					return postFormNoAuthRaw(t, s, tc.path, v, status)
				}
				return postJSONNoAuthRaw(t, s, tc.path, map[string]any{"token": secret, "nda_accepted": accept, "nda_accepted_by": "Reviewer"}, status)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			denied := request(token, false, 403)
			if strings.Contains(denied.Body.String(), owner.pkg.ID) || strings.Contains(denied.Body.String(), token) {
				t.Fatal("consent denial disclosed package or credential")
			}
			accepted := request(token, true, 200)
			if accepted.Header().Get("Cache-Control") != "no-store" || accepted.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("authorized token response became cacheable or referrer-bearing")
			}
			content := accepted.Body.Bytes()
			if tc.archive {
				z, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
				if err != nil || len(z.File) == 0 {
					t.Fatal("authorized download did not return its package archive", err)
				}
				content = nil
				for _, file := range z.File {
					r, err := file.Open()
					if err != nil {
						t.Fatal(err)
					}
					entry, readErr := io.ReadAll(r)
					closeErr := r.Close()
					if readErr != nil || closeErr != nil {
						t.Fatal("could not inspect authorized export", readErr, closeErr)
					}
					content = append(content, entry...)
				}
			} else if tc.form {
				assertNoStoreHTMLHeaders(t, accepted)
			}
			storedHash := before.CustomerPortalAccess[access.ID].Hash
			if storedHash == "" || !bytes.Contains(content, []byte(owner.pkg.ID)) || bytes.Contains(content, []byte(foreign.pkg.ID)) || bytes.Contains(content, []byte(token)) || bytes.Contains(content, []byte(storedHash)) || bytes.Contains(content, []byte("<script>unsafe()</script>")) {
				t.Fatal("authorized output omitted its scoped package or exposed foreign/private content")
			}
			wrong := token[:len(token)-1] + "x"
			if wrong == token {
				wrong = token[:len(token)-1] + "y"
			}
			request(wrong, true, 401)
			after, err := factory.Snapshot()
			v := after.CustomerPortalAccess[access.ID]
			if err != nil || v.AccessCount != 1 || v.FailedAccessCount != 1 || v.NDAAcceptedAt == nil || v.NDAAcceptedBy != "Reviewer" || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+5 || !reflect.DeepEqual(after.AuditEntries[foreign.actor.TenantID], before.AuditEntries[foreign.actor.TenantID]) || len(after.Idempotency) != 0 {
				t.Fatal("token policy changed consent, selected counters or exact audit semantics", err)
			}
			entries := after.AuditEntries[owner.actor.TenantID]
			for _, e := range entries[len(entries)-3 : len(entries)-1] {
				if e.EntryType != tc.audit || e.ActorID != access.ID || e.PayloadHash != owner.pkg.ManifestHash {
					t.Fatal("route selected the wrong central action or audit binding")
				}
			}
			if _, err := ports.RevokePortalAccess(t.Context(), owner.actor, access.ID); err != nil {
				t.Fatal(err)
			}
			revoked, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			request(token, true, 401)
			final, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(revoked, final) {
				t.Fatal("revoked token retained authority or mutated access state", err)
			}
		})
	}
}

func TestPortalPublicFormExposesNoPackageAndConsumesNoToken(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPortalFixtureScope(t, ledger, "Owner")
	ports := portalRegressionPorts(ledger)
	_, token, err := ports.CreatePortalAccess(t.Context(), owner.actor, portalFixtureInput(owner))
	if err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.portalTokenCommands = ports
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	form := getRawNoAuth(t, s, "/v1/customer-portal/package/view", 200)
	assertNoStoreHTMLHeaders(t, form)
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || strings.Contains(form.Body.String(), token) || strings.Contains(form.Body.String(), owner.pkg.ID) {
		t.Fatal("static public form disclosed a package or acquired token authority", err)
	}
}
