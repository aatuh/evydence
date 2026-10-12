package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/application"
)

func newNativeIngestionAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeEvidenceReadAuthorizationFixture(t)
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.objects = &signatureFixtureStore{Store: store}
	clock := application.ClockFunc(func() time.Time { return f.owner.release.CreatedAt })
	f.server.bindDocumentIngestionFixtureResources(f.objects, clock, false)
	f.server.bindSecurityDocumentFixtureResources(f.objects, clock)
	return f
}

func newNativeBuildAttestationAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeReleaseAuthorizationFixture(t)
	payload, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	f.raw, err = json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "recorded-only", "sig": "c2ln"}}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func addNativeIngestionAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation, suffix, body string
		status                  int
	}{
		{"linkEvidence", "link", `{"target_type":"product","target_id":%q}`, 201},
		{"supersedeEvidence", "supersede", `{"replacement_evidence_id":%q,"reason":"Reviewed"}`, 201},
		{"recordEvidenceLifecycleEvent", "lifecycle-events", `{"action":"amendment","reason":"Reviewed","replacement_id":%q}`, 201},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeEvidenceReadAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			id := f.owner.product.ID
			if tc.operation != "linkEvidence" {
				id = f.evidence.replacement.ID
			}
			return "/v1/evidence/" + f.evidence.original.ID + "/" + tc.suffix, []byte(fmt.Sprintf(tc.body, id))
		}, tc.status, 404)
	}
	for _, tc := range []struct {
		operation, path string
		body            func(nativeAuthorizationFixture) string
		audits          int
	}{
		{"uploadSBOM", "/v1/sboms", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"release_id":%q,"payload":{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one","purl":"pkg:generic/one@1"}]}}`, f.owner.release.ID)
		}, 2},
		{"uploadVEX", "/v1/vex", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"release_id":%q,"payload":%s}`, f.owner.release.ID, f.evidence.payload)
		}, 2},
		{"uploadVulnerabilityScan", "/v1/vulnerability-scans", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":%q,"findings":[{"vulnerability":"CVE-2026-2","component":"pkg:generic/one@1","severity":"high","state":"open"}]}`, f.owner.release.ID)
		}, 2},
		{"uploadOpenAPIContract", "/v1/openapi-contracts", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"product_id":%q,"release_id":%q,"version":"2","spec":{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{"/items":{"get":{"operationId":"listItems","responses":{"200":{"description":"ok"}}}}}}}`, f.owner.product.ID, f.owner.release.ID)
		}, 2},
		{"uploadSecurityScan", "/v1/security-scans", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"product_id":%q,"release_id":%q,"category":"secret_scan","format":"generic","scanner":"fixture","target_ref":"api","payload":{"findings":[{"severity":"high"}]}}`, f.owner.product.ID, f.owner.release.ID)
		}, 2},
		{"uploadAPISecurityScan", "/v1/api-security-scans", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"product_id":%q,"release_id":%q,"format":"generic","scanner":"fixture","target_ref":"api","payload":{"findings":[{"severity":"high"}]}}`, f.owner.product.ID, f.owner.release.ID)
		}, 2},
		{"uploadManualSecurityDocument", "/v1/security-documents", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"product_id":%q,"release_id":%q,"document_type":"security_review","title":"Reviewed","sensitivity":"restricted","media_type":"application/json","payload":{"note":"Recorded review"}}`, f.owner.product.ID, f.owner.release.ID)
		}, 2},
	} {
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, newNativeIngestionAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) { return tc.path, []byte(tc.body(f)) }, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: tc.audits, payloadStages: 1})
	}
	for _, tc := range []struct {
		operation, path, file string
		audits                int
	}{
		{"uploadSPDXSBOM", "/v1/sboms/spdx", "../../app/parsers/spdx/testdata/spdx-2.3-example.json", 2},
		{"uploadCycloneDXVEX", "/v1/vex/cyclonedx", "../../app/parsers/vex/testdata/cyclonedx-vex/official-vex-1.4.json", 2},
	} {
		fixture := func(t *testing.T) nativeAuthorizationFixture {
			f := newNativeIngestionAuthorizationFixture(t)
			raw, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			f.raw = raw
			return f
		}
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, fixture, func(f nativeAuthorizationFixture) (string, []byte) {
			return tc.path, []byte(fmt.Sprintf(`{"release_id":%q,"payload":%s}`, f.owner.release.ID, f.raw))
		}, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: tc.audits, payloadStages: 1})
	}
	cases["uploadBuildAttestation"] = nativeMutationAuthorizationFixtureCase("uploadBuildAttestation", newNativeBuildAttestationAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/builds/" + f.build.ID + "/attestations", f.raw
	}, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: 2})
}
