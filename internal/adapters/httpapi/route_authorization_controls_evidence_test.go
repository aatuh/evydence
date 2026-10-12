package httpapi

import (
	"fmt"
	"testing"
)

func newNativeControlAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedControlFixtureScope(t, ledger, "Owner"), seedControlFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.control = owner
	return f
}

func newNativeReportAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedPackageReportFixtureScope(t, ledger, "Owner"), seedPackageReportFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.control, f.report = owner.controlFixtureScope, owner
	return f
}

func addNativeControlsAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation string
		index     int
		foreign   int
	}{
		{"createControlFramework", 0, 0},
		{"createSecurityControl", 1, 404},
		{"installControlFrameworkTemplatePack", 2, 0},
		{"linkControlEvidence", 3, 404},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeControlAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := controlFixtureRequests(f.control)[tc.index]
			return r.path, []byte(r.body)
		}, 201, tc.foreign)
	}
	for _, tc := range []struct {
		operation, path string
		foreign         int
		contains        func(nativeAuthorizationFixture) string
	}{
		{"listControlFrameworks", "/v1/control-frameworks", 200, func(f nativeAuthorizationFixture) string { return f.control.framework.ID }},
		{"getSecurityControl", "/v1/controls/%s", 404, func(f nativeAuthorizationFixture) string { return f.control.control.ID }},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeControlAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			if tc.operation == "getSecurityControl" {
				return fmt.Sprintf(tc.path, f.control.control.ID)
			}
			return tc.path
		}, tc.contains, tc.foreign)
	}
	for _, tc := range []struct {
		operation, path string
		contains        func(nativeAuthorizationFixture) string
	}{
		{"craReadinessReport", "/v1/reports/cra-readiness?product_id=%s&release_id=%s", func(f nativeAuthorizationFixture) string { return f.owner.release.ID }},
		{"controlCoverageReport", "/v1/reports/control-coverage?product_id=%s&release_id=%s", func(f nativeAuthorizationFixture) string { return f.control.control.ID }},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeReportAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(tc.path, f.owner.product.ID, f.owner.release.ID)
		}, tc.contains, 404)
	}
	cases["listControlEvidence"] = nativeReadAuthorizationFixtureCase("listControlEvidence", newNativeReportAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/control-evidence" }, func(f nativeAuthorizationFixture) string { return f.control.control.ID }, 200)
	for _, tc := range []struct{ operation, suffix string }{
		{"getReleaseBundle", ""}, {"getReleaseBundleManifest", "/manifest"},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeReportAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			return "/v1/release-bundles/" + f.report.bundle.ID + tc.suffix
		}, func(f nativeAuthorizationFixture) string { return f.owner.release.ID }, 404)
	}
	cases["listExceptions"] = nativeReadAuthorizationFixtureCase("listExceptions", newNativeReportAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/exceptions" }, func(f nativeAuthorizationFixture) string { return f.report.exception.ID }, 200)
	cases["listVulnerabilityDecisions"] = nativeReadAuthorizationFixtureCase("listVulnerabilityDecisions", newNativeReportAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/vulnerability-decisions" }, func(f nativeAuthorizationFixture) string { return f.report.decision.ID }, 200)
}

func newNativeEvidenceReadAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedEvidenceReadFixtureScope(t, ledger, "Owner"), seedEvidenceReadFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product, release: owner.release, evidence: owner.original}, operationsFixtureScope{actor: foreign.actor, product: foreign.product, release: foreign.release, evidence: foreign.original})
	f.evidence = owner
	return f
}

func addNativeEvidenceReadAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation, path string
		id              func(nativeAuthorizationFixture) string
	}{
		{"getSBOM", "/v1/sboms/", func(f nativeAuthorizationFixture) string { return f.evidence.sbom.ID }},
		{"getOpenAPIContract", "/v1/openapi-contracts/", func(f nativeAuthorizationFixture) string { return f.evidence.contract.ID }},
		{"getVulnerabilityScan", "/v1/vulnerability-scans/", func(f nativeAuthorizationFixture) string { return f.evidence.scan.ID }},
		{"getVEX", "/v1/vex/", func(f nativeAuthorizationFixture) string { return f.evidence.vex.ID }},
		{"getVEXImportReport", "/v1/vex/", func(f nativeAuthorizationFixture) string { return f.evidence.vex.ID }},
		{"listEvidenceLifecycleEvents", "/v1/evidence/", func(f nativeAuthorizationFixture) string { return f.evidence.original.ID }},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeEvidenceReadAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			path := tc.path + tc.id(f)
			if tc.operation == "getVEXImportReport" {
				path += "/import-report"
			}
			if tc.operation == "listEvidenceLifecycleEvents" {
				path += "/lifecycle-events"
			}
			return path
		}, tc.id, 404)
	}
	cases["listSBOMComponents"] = nativeReadAuthorizationFixtureCase("listSBOMComponents", newNativeEvidenceReadAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/sbom-components" }, func(f nativeAuthorizationFixture) string { return f.evidence.sbom.ID }, 200)
}
