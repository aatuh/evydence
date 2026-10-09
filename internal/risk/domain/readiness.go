package domain

import (
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrReadinessValidation = errors.New("invalid release readiness snapshot")

const ReadinessSnapshotVersion = "release-readiness-snapshot.v1.0.0"

// ReadinessSnapshot is one committed, tenant-scoped set of facts. Adapters
// gather facts; the Risk domain owns their policy interpretation.
type ReadinessSnapshot struct {
	SnapshotVersion             string
	TenantID                    string
	ProductID                   string
	ReleaseID                   string
	HasArtifact                 bool
	HasSBOM                     bool
	HasVulnerabilityScan        bool
	HasArtifactDigest           bool
	HasVerifiedSignedBundle     bool
	HasPassedBuild              bool
	HasVerifiedBuildAttestation bool
	UnhandledCritical           bool
	UnhandledHigh               bool
	MissingCustomerStatementIDs []string
	MissingNotAffectedReasonIDs []string
	IncompleteExceptionIDs      []string
	PackageCount                int
	InvalidPackageOrProfileIDs  []string
}

// EvaluateReadinessSnapshot converts a validated, committed fact snapshot to
// the canonical built-in policy result without persistence or network access.
func EvaluateReadinessSnapshot(snapshot ReadinessSnapshot, createdAt time.Time) (PolicyEvaluation, error) {
	if snapshot.SnapshotVersion != ReadinessSnapshotVersion || snapshot.TenantID == "" || snapshot.ProductID == "" || snapshot.ReleaseID == "" || snapshot.PackageCount < 0 || createdAt.IsZero() {
		return PolicyEvaluation{}, ErrReadinessValidation
	}
	checks := readinessPolicyChecks(snapshot)
	return PolicyEvaluation{
		TenantID: snapshot.TenantID, ReleaseID: snapshot.ReleaseID,
		Result: readinessPolicyResult(checks), PolicySet: PolicySetVersion,
		Checks: checks, CreatedAt: createdAt.UTC(),
	}, nil
}

func readinessPolicyChecks(snapshot ReadinessSnapshot) []PolicyCheck {
	checks := []PolicyCheck{
		presenceCheck(snapshot.HasArtifact, "release_has_artifact", "high", "artifact", "artifact evidence is linked to the release", "release artifact evidence is missing", "Register an artifact digest and link it to release evidence such as SBOM, scan, build output, or artifact digest evidence."),
		presenceCheck(snapshot.HasSBOM, "release_requires_sbom", "high", "sbom", "sbom evidence exists", "sbom evidence is missing", "Upload sbom evidence for this release."),
		presenceCheck(snapshot.HasVulnerabilityScan, "release_requires_vulnerability_scan", "high", "vulnerability_scan", "vulnerability_scan evidence exists", "vulnerability_scan evidence is missing", "Upload vulnerability_scan evidence for this release."),
		presenceCheck(snapshot.HasArtifactDigest, "release_requires_artifact_digest", "high", "artifact_digest", "artifact digest evidence is linked to the release", "release artifact digest evidence is missing", "Register an artifact digest and link it to release evidence."),
		presenceCheck(snapshot.HasVerifiedSignedBundle, "release_requires_signed_bundle", "high", "signed_release_bundle", "signed release bundle exists", "signed release bundle is missing", "Generate a release bundle after required evidence is recorded."),
		presenceCheck(snapshot.HasPassedBuild, "release_requires_passed_build", "high", "passed_build", "passed build is linked to a release artifact digest", "no passed build with output digest linked to the release was found", "Upload a passed build run whose output digest matches a release artifact digest."),
		presenceCheck(snapshot.HasVerifiedBuildAttestation, "release_requires_build_attestation", "high", "build_attestation", "verified build attestation receipt and subject match a release artifact digest", "no attestation has a passed DSSE/in-toto receipt and a subject matching a release artifact digest", "Upload a supported DSSE/in-toto attestation, verify it with a configured root policy, and ensure its subject digest matches a release artifact digest."),
		inversePresenceCheck(snapshot.UnhandledCritical, "critical_exploitable_blocks_release", "critical", "vulnerability_decision", "no open critical findings recorded", "open critical finding requires remediation, a valid VEX decision, or an approved unexpired exception", "Record a fixed or not_affected vulnerability decision, upload VEX evidence, remediate the finding, or approve an unexpired scoped exception."),
		inversePresenceCheck(snapshot.UnhandledHigh, "high_findings_require_triage", "high", "vulnerability_decision", "no unhandled open high findings recorded", "open high finding requires a valid decision, remediation, or an approved unexpired exception", "Record a fixed or not_affected vulnerability decision, upload VEX evidence, remediate the finding, or approve an unexpired scoped exception."),
		missingIDsCheck(snapshot.MissingCustomerStatementIDs, "customer_visible_decisions_require_statements", "high", "customer-visible decisions have required impact statements", "customer-visible decisions require an impact statement suitable for package summaries", "Create a superseding customer-visible decision with a clear impact statement and no internal-only notes in customer-facing fields."),
		missingIDsCheck(snapshot.MissingNotAffectedReasonIDs, "not_affected_decisions_require_justification", "high", "not_affected decisions have recorded justifications", "not_affected decisions require a recorded justification", "Create a superseding not_affected decision with a specific technical justification."),
		missingIDsCheck(snapshot.IncompleteExceptionIDs, "exceptions_require_owner_reason_expiry_and_approval", "high", "release exceptions have required completeness fields", "exceptions must include owner, reason, expiry, and approval metadata when approved", "Create a complete exception with owner, reason, future expiry, and an audited approval transition."),
	}
	invalidPackages := normalizedIDs(snapshot.InvalidPackageOrProfileIDs)
	switch {
	case len(invalidPackages) > 0:
		checks = append(checks, PolicyCheck{Name: "package_redaction_profile_valid", Result: "failed", Severity: "high", Missing: invalidPackages, Explanation: "one or more customer packages has an expired package or redaction profile that does not explicitly exclude sensitive fields", Remediation: "Create a new package with the customer_safe or security_review preset, or configure explicit allowed types and sensitive-field exclusions."})
	case snapshot.PackageCount == 0:
		checks = append(checks, PolicyCheck{Name: "package_redaction_profile_valid", Result: "passed", Severity: "medium", Explanation: "no customer package is recorded for this release; redaction profile validation applies when a package exists"})
	default:
		checks = append(checks, PolicyCheck{Name: "package_redaction_profile_valid", Result: "passed", Severity: "high", Explanation: "customer package redaction profiles are explicit and exclude sensitive fields"})
	}
	return checks
}

func presenceCheck(passed bool, name, severity, missing, passedExplanation, failedExplanation, remediation string) PolicyCheck {
	if passed {
		return PolicyCheck{Name: name, Result: "passed", Severity: severity, Explanation: passedExplanation}
	}
	return PolicyCheck{Name: name, Result: "failed", Severity: severity, Missing: []string{missing}, Explanation: failedExplanation, Remediation: remediation}
}

func inversePresenceCheck(blocked bool, name, severity, missing, passedExplanation, failedExplanation, remediation string) PolicyCheck {
	return presenceCheck(!blocked, name, severity, missing, passedExplanation, failedExplanation, remediation)
}

func missingIDsCheck(values []string, name, severity, passedExplanation, failedExplanation, remediation string) PolicyCheck {
	missing := normalizedIDs(values)
	if len(missing) == 0 {
		return PolicyCheck{Name: name, Result: "passed", Severity: severity, Explanation: passedExplanation}
	}
	return PolicyCheck{Name: name, Result: "failed", Severity: severity, Missing: missing, Explanation: failedExplanation, Remediation: remediation}
}

func readinessPolicyResult(checks []PolicyCheck) string {
	for _, check := range checks {
		if check.Result == "failed" {
			return "failed"
		}
	}
	return "passed"
}

func normalizedIDs(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
