package httpapi

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func newNativePortalAdministrationAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedPortalFixtureScope(t, ledger, "Owner"), seedPortalFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.portal = owner
	access, _, err := portalRegressionPorts(ledger).CreatePortalAccess(t.Context(), owner.actor, portalFixtureInput(owner))
	if err != nil {
		t.Fatal(err)
	}
	f.portalAccess = portalAccessFromQuery(access)
	return f
}

func nativeCustomerAccessAuthorizationCase(operation string, path func(nativeAuthorizationFixture) string, archive bool) func(*testing.T) {
	return func(t *testing.T) {
		f := newNativeQuestionnaireAuthorizationFixture(t)
		const privateCanary = "private-package-authorization-canary"
		if _, err := createEvidenceFixture(t.Context(), f.ledger, f.owner.actor, evidenceFixtureInput{ProductID: f.owner.product.ID, ReleaseID: f.owner.release.ID, Type: "manual", Title: "Public scoped evidence", PayloadHash: "sha256:" + strings.Repeat("c", 64), Metadata: map[string]any{"internal_notes": privateCanary}}); err != nil {
			t.Fatal(err)
		}
		pkg, err := createCustomerPackageFixture(t.Context(), f.ledger, f.owner.actor, packageapp.CreateCustomerPackageInput{ProductID: f.owner.product.ID, ReleaseID: f.owner.release.ID, RedactionProfileID: f.questionnaire.pkg.RedactionProfileID, Title: "Scoped customer review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		f.questionnaire.pkg = pkg
		owner := nativeOperationPrincipal(t, operation, f.owner.actor)
		foreign := nativeOperationPrincipal(t, operation, f.foreign.actor)
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		denied, revoked := owner, owner
		denied.Scopes = nil
		revoked.KeyID, revoked.UserID, revoked.ResourceGrants = "", "revoked-human", nil
		for _, tc := range []struct {
			actor  domain.Actor
			status int
		}{{denied, 403}, {revoked, 403}, {foreign, 404}} {
			out := f.request(t, operation, http.MethodGet, path(f), tc.actor, nil, tc.status)
			if strings.Contains(out.Body.String(), `"data"`) {
				t.Fatal("unauthorized package access disclosed resource data")
			}
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("denied package access changed counters, audit or repository state", err)
			}
		}
		out := f.request(t, operation, http.MethodGet, path(f), owner, nil, 200)
		content := out.Body.Bytes()
		if archive {
			if out.Header().Get("Content-Type") != "application/zip" || out.Header().Get("X-Evydence-Archive-Hash") == "" {
				t.Fatal("authorized download lost its archive contract")
			}
			z, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
			if err != nil || len(z.File) == 0 {
				t.Fatal("authorized download is not a package archive", err)
			}
			content = nil
			for _, file := range z.File {
				r, err := file.Open()
				if err != nil {
					t.Fatal(err)
				}
				b, readErr := io.ReadAll(r)
				closeErr := r.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal(readErr, closeErr)
				}
				content = append(content, b...)
			}
		}
		// Redaction policy metadata legitimately names excluded fields. Check
		// the actual private value, not a public policy-field declaration.
		if !bytes.Contains(content, []byte(f.questionnaire.pkg.ID)) || bytes.Contains(content, []byte(f.foreign.product.ID)) || bytes.Contains(content, []byte(privateCanary)) {
			t.Fatal("package output omitted owned scope or exposed foreign/private fields")
		}
		after, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		id := f.questionnaire.pkg.ID
		if after.CustomerPackages[id].AccessCount != before.CustomerPackages[id].AccessCount+1 || len(after.AuditEntries[owner.TenantID]) != len(before.AuditEntries[owner.TenantID])+1 {
			t.Fatal("audited package access lost its exact counter/audit effect")
		}
		entry := after.AuditEntries[owner.TenantID][len(after.AuditEntries[owner.TenantID])-1]
		if entry.EntryType != "customer_package.accessed" || entry.SubjectID != id || entry.ActorID != owner.KeyID || entry.PayloadHash != f.questionnaire.pkg.ManifestHash {
			t.Fatal("package access audit lost its owned principal/manifest binding")
		}
		accessed := after.CustomerPackages[id]
		accessed.AccessCount = before.CustomerPackages[id].AccessCount
		after.CustomerPackages[id] = accessed
		after.AuditEntries[owner.TenantID] = before.AuditEntries[owner.TenantID]
		if !reflect.DeepEqual(before, after) {
			t.Fatal("package access changed immutable or unrelated state")
		}
	}
}

func addNativePackageAccessAuthorizationCases(cases map[string]func(*testing.T)) {
	cases["getCustomerPackage"] = nativeCustomerAccessAuthorizationCase("getCustomerPackage", func(f nativeAuthorizationFixture) string { return "/v1/customer-packages/" + f.questionnaire.pkg.ID }, false)
	cases["downloadCustomerPackage"] = nativeCustomerAccessAuthorizationCase("downloadCustomerPackage", func(f nativeAuthorizationFixture) string {
		return "/v1/customer-packages/" + f.questionnaire.pkg.ID + "/download"
	}, true)
	cases["securityReviewPackageReport"] = nativeCustomerAccessAuthorizationCase("securityReviewPackageReport", func(f nativeAuthorizationFixture) string {
		return "/v1/reports/security-review-package?package_id=" + f.questionnaire.pkg.ID
	}, false)
	cases["craReadinessHTMLPackage"] = nativeMutationAuthorizationFixtureCase("craReadinessHTMLPackage", newNativeReportAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return fmt.Sprintf("/v1/reports/cra-readiness-html?product_id=%s&release_id=%s", f.owner.product.ID, f.owner.release.ID), nil
	}, nativeMutationExpectation{status: 200, foreignStatus: 404, auditDelta: 1, method: http.MethodGet})
	cases["createCustomerPortalAccess"] = nativeMutationAuthorizationFixtureCase("createCustomerPortalAccess", newNativePortalAdministrationAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/customer-portal/access", []byte(portalFixtureBody(f.portal))
	}, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: 1, resultField: "access"})
	cases["revokeCustomerPortalAccess"] = nativeWriteAuthorizationFixtureCase("revokeCustomerPortalAccess", newNativePortalAdministrationAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/customer-portal/access/" + f.portalAccess.ID + "/revoke", []byte(`{}`)
	}, 200, 404)
	cases["listCustomerPortalAccess"] = nativeReadAuthorizationFixtureCase("listCustomerPortalAccess", newNativePortalAdministrationAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/customer-portal/access" }, func(f nativeAuthorizationFixture) string { return f.portalAccess.ID }, 200)
	for _, tc := range []struct {
		operation, path string
		cyclonedx       bool
	}{
		{"previewVEXImport", "/v1/vex/preview", false}, {"previewCycloneDXVEXImport", "/v1/vex/cyclonedx/preview", true},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixturePayloadCase(tc.operation, http.MethodPost, newNativeEvidenceReadAuthorizationFixture, func(nativeAuthorizationFixture) string { return tc.path }, func(f nativeAuthorizationFixture) []byte {
			payload := f.evidence.payload
			if tc.cyclonedx {
				payload = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-1","analysis":{"state":"resolved"},"affects":[{"ref":"pkg:generic/one@1"}]}]}`)
			}
			return []byte(fmt.Sprintf(`{"release_id":%q,"payload":%s}`, f.owner.release.ID, payload))
		}, func(f nativeAuthorizationFixture) string { return f.owner.release.ID }, 404)
	}
	importFixture := func(t *testing.T) nativeAuthorizationFixture {
		f := newNativeAuthorizationFixture(t)
		// Source coordinates are untrusted portable labels, not authority to
		// dereference another tenant. Only a local manifest receipt is created.
		manifest := map[string]any{"bundle_version": domain.EvidenceBundleSchemaVersion, "evidence_ids": []string{f.foreign.evidence.ID}}
		hash, err := application.NormalizedJSONHash(manifest)
		if err != nil {
			t.Fatal(err)
		}
		f.raw, err = json.Marshal(map[string]any{"tenant_id": f.foreign.actor.TenantID, "release_id": f.foreign.release.ID, "evidence_ids": []string{f.foreign.evidence.ID}, "manifest": manifest, "manifest_hash": hash})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	cases["importEvidenceBundle"] = nativeWriteAuthorizationFixtureCase("importEvidenceBundle", importFixture, func(f nativeAuthorizationFixture) (string, []byte) { return "/v1/evidence-bundles/import", f.raw }, 201, 0)
	cases["createSaaSEditionProfile"] = func(t *testing.T) {
		f := newNativeAuthorizationFixture(t)
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		path := "/v1/saas/profiles"
		body := []byte(fmt.Sprintf(`{"name":"Hosted","region":"eu","admin_tenant_id":%q,"isolation_model":"shared-control-plane"}`, f.foreign.actor.TenantID))
		for _, actor := range []domain.Actor{f.owner.actor, f.foreign.actor, {TenantID: f.owner.actor.TenantID, UserID: "tenant-admin", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: f.owner.actor.TenantID, Scopes: []string{"*"}}}}} {
			f.request(t, "createSaaSEditionProfile", http.MethodPost, path, actor, body, 403)
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("tenant capability created an instance-owned profile", err)
			}
		}
		instance := nativeOperationPrincipal(t, "createSaaSEditionProfile", f.owner.actor)
		out := f.request(t, "createSaaSEditionProfile", http.MethodPost, path, instance, body, 201)
		after, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		id := dataField(t, out.Body.String(), "id")
		assertNativeMutationPersisted(t, "createSaaSEditionProfile", after, id, envelope.Data)
		if after.SaaSEditionProfiles[id].TenantID != instance.TenantID || after.SaaSEditionProfiles[id].AdminTenantID != f.foreign.actor.TenantID || len(after.AuditEntries[instance.TenantID]) != len(before.AuditEntries[instance.TenantID])+1 {
			t.Fatal("explicit instance authority lost local ownership or admin target")
		}
	}
}
