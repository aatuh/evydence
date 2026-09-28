package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const ReadinessReportSnapshotVersion = "release-readiness-report-snapshot.v1.0.0"

// ReadinessReportSnapshot is the complete, immutable input for one readiness
// report. Adapters must populate it from one committed transaction snapshot or
// an equivalently atomic projection. Report assembly never reads another
// context or mutates application state.
type ReadinessReportSnapshot struct {
	SnapshotVersion          string
	TenantID                 string
	ProductID                string
	ReleaseID                string
	Result                   string
	PolicySet                string
	Checks                   []packagedomain.PolicyCheckSnapshot
	BlockingFindings         []packagedomain.BlockingFinding
	AcceptedExceptions       []packagedomain.AcceptedExceptionSnapshot
	ActiveDecisionCount      int
	HasActiveCustomerPackage bool
}

// ReleaseReadinessReport renders a deterministic, read-only report from one
// committed snapshot. Reports are not receipts, so this operation deliberately
// performs no transaction, audit append, or other write.
func (s *Service) ReleaseReadinessReport(ctx context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseReadinessReport, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.ReleaseReadinessReport{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.ReleaseReadinessReport{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReadinessRead, application.ResourceReferences{}, true); err != nil {
		return packagedomain.ReleaseReadinessReport{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return packagedomain.ReleaseReadinessReport{}, ErrValidation
	}
	if s.projectionRefresher != nil {
		if err := s.projectionRefresher.RefreshPackageProjection(ctx, actor.TenantID); err != nil {
			return packagedomain.ReleaseReadinessReport{}, err
		}
	}
	snapshot, err := s.reader.ReadCommittedReadinessReportSnapshot(ctx, actor.TenantID, releaseID)
	if err != nil {
		return packagedomain.ReleaseReadinessReport{}, err
	}
	snapshot = cloneReadinessReportSnapshot(snapshot)
	if snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != releaseID {
		return packagedomain.ReleaseReadinessReport{}, ErrNotFound
	}
	if !validReadinessReportSnapshot(snapshot) {
		return packagedomain.ReleaseReadinessReport{}, ErrConflict
	}
	resources := application.ResourceReferences{ProductID: snapshot.ProductID, ReleaseID: snapshot.ReleaseID}
	if err := s.authorize(ctx, actor, ScopeReadinessRead, resources, false); err != nil {
		return packagedomain.ReleaseReadinessReport{}, err
	}

	gaps := make([]string, 0)
	failedPolicies := make([]string, 0)
	for _, check := range snapshot.Checks {
		gaps = append(gaps, check.Missing...)
		if check.Result == "failed" {
			failedPolicies = append(failedPolicies, check.Name)
		}
	}
	gaps = sortedUniqueStrings(gaps)
	failedPolicies = sortedUniqueStrings(failedPolicies)
	knownLimitations := releaseReadinessKnownLimitations()
	nonClaims := releaseReadinessNonClaims()
	report := packagedomain.ReleaseReadinessReport{
		ReportType: "release_readiness", TemplateVersion: packagedomain.ReleaseReadinessTemplateVersion,
		ReleaseID: snapshot.ReleaseID, Result: snapshot.Result, PolicySet: snapshot.PolicySet,
		Summary:            releaseReadinessSummary(snapshot.Result, snapshot.PolicySet, len(snapshot.BlockingFindings), len(gaps), len(failedPolicies)),
		Checks:             clonePolicyCheckSnapshots(snapshot.Checks),
		Sections:           releaseReadinessSections(snapshot, gaps, failedPolicies, knownLimitations),
		BlockingFindings:   cloneBlockingFindings(snapshot.BlockingFindings),
		AcceptedExceptions: cloneAcceptedExceptions(snapshot.AcceptedExceptions),
		Gaps:               append([]string(nil), gaps...), MissingEvidence: append([]string(nil), gaps...),
		FailedPolicies: append([]string(nil), failedPolicies...), KnownLimitations: append([]string(nil), knownLimitations...),
		NonClaims:   append([]string(nil), nonClaims...),
		Assumptions: []string{"This report supports compliance readiness and technical evidence review; it is not a legal compliance conclusion."},
		Limitations: append([]string(nil), knownLimitations...), GeneratedAt: s.clock.Now().UTC(),
	}
	return report, nil
}

func validReadinessReportSnapshot(snapshot ReadinessReportSnapshot) bool {
	if snapshot.SnapshotVersion != ReadinessReportSnapshotVersion || strings.TrimSpace(snapshot.ProductID) == "" || snapshot.ActiveDecisionCount < 0 || (snapshot.Result != "passed" && snapshot.Result != "failed") || strings.TrimSpace(snapshot.PolicySet) == "" {
		return false
	}
	for _, check := range snapshot.Checks {
		if strings.TrimSpace(check.Name) == "" || (check.Result != "passed" && check.Result != "failed") {
			return false
		}
	}
	for _, finding := range snapshot.BlockingFindings {
		if strings.TrimSpace(finding.FindingID) == "" || finding.ReleaseID != snapshot.ReleaseID {
			return false
		}
	}
	for _, exception := range snapshot.AcceptedExceptions {
		if strings.TrimSpace(exception.ID) == "" || exception.TenantID != snapshot.TenantID || exception.ReleaseID != snapshot.ReleaseID || !exception.Approved {
			return false
		}
	}
	return true
}

func releaseReadinessSummary(result, policySet string, blockingCount, missingCount, failedCount int) packagedomain.ReadinessSummary {
	if result == "passed" {
		return packagedomain.ReadinessSummary{
			Headline: "Recorded release evidence satisfies the current built-in readiness checks.", Result: result,
			HumanSummary: "The report found no blocking policy failures in the recorded release evidence. Review the limitations and non-claims before sharing externally.", PolicySet: policySet,
		}
	}
	return packagedomain.ReadinessSummary{
		Headline: "Recorded release evidence has readiness blockers or missing inputs.", Result: result,
		HumanSummary: fmt.Sprintf("The report found %d failed policy checks, %d missing evidence inputs, and %d blocking findings in the recorded release evidence.", failedCount, missingCount, blockingCount),
		PolicySet:    policySet,
	}
}

func releaseReadinessKnownLimitations() []string {
	return []string{
		"Readiness is based only on evidence, decisions, exceptions, bundles, and build records stored in this Evydence instance.",
		"SBOM presence does not prove component inventory completeness.",
		"Scanner output is submitted evidence and is not treated as authoritative vulnerability truth.",
		"Build provenance and attestations are evaluated from recorded metadata and configured trust material only.",
		"Customer package shareability depends on the generated package redaction profile, expiry, and operator review.",
	}
}

func releaseReadinessNonClaims() []string {
	return []string{
		"This report supports technical evidence review and compliance readiness only.",
		"It is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.",
	}
}

func releaseReadinessSections(snapshot ReadinessReportSnapshot, missingEvidence, failedPolicies, knownLimitations []string) []packagedomain.ReadinessSection {
	checks := readinessChecksByName(snapshot.Checks)
	return []packagedomain.ReadinessSection{
		readinessSection("release_evidence", "Release Evidence", []packagedomain.ReadinessQuestion{
			readinessQuestionForCheck(checks["release_has_artifact"], "release_has_artifact", "Is a release artifact linked?", "Artifact evidence is linked to the release.", "Release artifact evidence is missing."),
			readinessQuestionForCheck(checks["release_requires_artifact_digest"], "artifact_digest", "Are artifact digests present?", "Artifact digest evidence is linked to the release.", "Release artifact digest evidence is missing."),
			readinessQuestionForCheck(checks["release_requires_sbom"], "sbom", "Is there an SBOM for this release?", "SBOM evidence is recorded for this release.", "SBOM evidence is missing for this release."),
			readinessQuestionForCheck(checks["release_requires_vulnerability_scan"], "vulnerability_scan", "Is there a vulnerability scan?", "Vulnerability scan evidence is recorded for this release.", "Vulnerability scan evidence is missing for this release."),
		}),
		readinessSection("risk_decisions", "Vulnerability Decisions", []packagedomain.ReadinessQuestion{
			readinessQuestionForCheck(checks["critical_exploitable_blocks_release"], "critical_findings_triaged", "Are open critical findings triaged?", "No unhandled open critical findings are recorded.", "One or more open critical findings require a valid decision, remediation, or approved unexpired exception."),
			readinessQuestionForCheck(checks["high_findings_require_triage"], "high_findings_triaged", "Are open high findings triaged?", "No unhandled open high findings are recorded.", "One or more open high findings require a valid decision, remediation, or approved unexpired exception."),
			readinessDecisionQuestion(snapshot.ActiveDecisionCount, len(snapshot.BlockingFindings)),
			readinessQuestionForCheck(checks["customer_visible_decisions_require_statements"], "customer_visible_decision_statements", "Do customer-visible decisions have review-safe statements?", "Customer-visible decisions have required impact statements.", "One or more customer-visible decisions is missing an impact statement."),
			readinessQuestionForCheck(checks["not_affected_decisions_require_justification"], "not_affected_justifications", "Do not_affected decisions include justifications?", "not_affected decisions include recorded justifications.", "One or more not_affected decisions is missing a justification."),
			readinessExceptionQuestion(snapshot.AcceptedExceptions),
			readinessQuestionForCheck(checks["exceptions_require_owner_reason_expiry_and_approval"], "exception_completeness", "Are exceptions complete?", "Release exceptions have required owner, reason, expiry, and approval metadata.", "One or more exceptions is incomplete."),
		}),
		readinessSection("provenance", "Build Provenance And Bundle", []packagedomain.ReadinessQuestion{
			readinessQuestionForCheck(checks["release_requires_passed_build"], "passed_build", "Is passed build provenance attached?", "A passed build is linked to a release artifact digest.", "No passed build with output digest linked to the release was found."),
			readinessQuestionForCheck(checks["release_requires_build_attestation"], "build_attestation", "Is there a trusted build attestation for a release artifact?", "A passed trusted-attestation receipt covers a registered release artifact digest.", "No passed trusted-attestation receipt covers a registered release artifact digest."),
			readinessQuestionForCheck(checks["release_requires_signed_bundle"], "signed_bundle", "Is there a signed release bundle?", "A signed release bundle exists for this release.", "A signed release bundle is missing for this release."),
		}),
		readinessSection("customer_review", "Customer Package Review", []packagedomain.ReadinessQuestion{
			readinessCustomerPackageQuestion(snapshot.HasActiveCustomerPackage),
			readinessQuestionForCheck(checks["package_redaction_profile_valid"], "package_redaction_profile_valid", "Is the customer package redaction profile valid?", "Recorded package redaction profiles are explicit and exclude sensitive fields, or no package exists yet.", "One or more packages has an expired or incomplete redaction profile."),
		}),
		readinessSection("gaps_and_limitations", "Gaps And Limitations", []packagedomain.ReadinessQuestion{
			readinessGapQuestion(missingEvidence, failedPolicies),
			{ID: "known_limitations", Question: "What limitations apply?", Answer: "Read the known_limitations and non_claims fields before using this report.", Status: "limited", KnownLimitations: append([]string(nil), knownLimitations...)},
		}),
	}
}

func readinessChecksByName(checks []packagedomain.PolicyCheckSnapshot) map[string]packagedomain.PolicyCheckSnapshot {
	result := make(map[string]packagedomain.PolicyCheckSnapshot, len(checks))
	for _, check := range checks {
		result[check.Name] = check
	}
	return result
}

func readinessSection(id, title string, questions []packagedomain.ReadinessQuestion) packagedomain.ReadinessSection {
	status := "passed"
	for _, question := range questions {
		switch question.Status {
		case "failed_policy":
			status = "failed"
		case "missing_evidence":
			if status != "failed" {
				status = "missing"
			}
		case "limited":
			if status == "passed" {
				status = "limited"
			}
		}
	}
	return packagedomain.ReadinessSection{ID: id, Title: title, Status: status, Summary: readinessSectionSummary(status), Questions: questions}
}

func readinessSectionSummary(status string) string {
	switch status {
	case "failed":
		return "One or more reviewer questions failed a policy check."
	case "missing":
		return "One or more reviewer questions is missing evidence."
	case "limited":
		return "This section has recorded limitations or non-blocking missing context."
	default:
		return "Recorded evidence satisfies this section."
	}
}

func readinessQuestionForCheck(check packagedomain.PolicyCheckSnapshot, id, question, passedAnswer, failedAnswer string) packagedomain.ReadinessQuestion {
	if check.Name == "" {
		return packagedomain.ReadinessQuestion{ID: id, Question: question, Answer: "No policy check was recorded for this question.", Status: "limited", KnownLimitations: []string{"Policy coverage for this question is not configured."}}
	}
	if check.Result == "passed" {
		return packagedomain.ReadinessQuestion{ID: id, Question: question, Answer: passedAnswer, Status: "passed", Checks: []string{check.Name}}
	}
	status := "failed_policy"
	if len(check.Missing) > 0 {
		status = "missing_evidence"
	}
	return packagedomain.ReadinessQuestion{ID: id, Question: question, Answer: failedAnswer, Status: status, Checks: []string{check.Name}, MissingEvidence: append([]string(nil), check.Missing...), FailedPolicies: []string{check.Name}}
}

func readinessDecisionQuestion(decisionCount, blockingCount int) packagedomain.ReadinessQuestion {
	if blockingCount > 0 {
		return packagedomain.ReadinessQuestion{ID: "vex_decisions_for_blockers", Question: "Are VEX or vulnerability decisions present for blocking findings?", Answer: fmt.Sprintf("%d blocking finding(s) still need a valid decision, remediation, or approved exception.", blockingCount), Status: "failed_policy", MissingEvidence: []string{"vulnerability_decision"}, FailedPolicies: []string{"critical_exploitable_blocks_release"}}
	}
	if decisionCount > 0 {
		return packagedomain.ReadinessQuestion{ID: "vex_decisions_for_blockers", Question: "Are VEX or vulnerability decisions present for blocking findings?", Answer: fmt.Sprintf("%d active vulnerability decision(s) are recorded for this release.", decisionCount), Status: "passed", Evidence: []string{"vulnerability_decision"}}
	}
	return packagedomain.ReadinessQuestion{ID: "vex_decisions_for_blockers", Question: "Are VEX or vulnerability decisions present for blocking findings?", Answer: "No active vulnerability decisions are recorded; no blocking findings currently require one.", Status: "limited", KnownLimitations: []string{"Decision evidence is only expected when findings require triage or customer-visible explanation."}}
}

func readinessExceptionQuestion(accepted []packagedomain.AcceptedExceptionSnapshot) packagedomain.ReadinessQuestion {
	if len(accepted) > 0 {
		return packagedomain.ReadinessQuestion{ID: "approved_exceptions", Question: "Are exceptions approved and unexpired?", Answer: fmt.Sprintf("%d approved unexpired exception(s) are accepted for this release.", len(accepted)), Status: "passed", Evidence: []string{"exception"}}
	}
	return packagedomain.ReadinessQuestion{ID: "approved_exceptions", Question: "Are exceptions approved and unexpired?", Answer: "No approved unexpired release exceptions are used by this report.", Status: "limited", KnownLimitations: []string{"No exception is needed when policy checks pass without an accepted exception."}}
}

func readinessCustomerPackageQuestion(hasPackage bool) packagedomain.ReadinessQuestion {
	if hasPackage {
		return packagedomain.ReadinessQuestion{ID: "customer_package_safe_to_share", Question: "Is a customer package available for review?", Answer: "A non-expired customer package is recorded for this release; review its redaction profile before sharing.", Status: "passed", Evidence: []string{"customer_package"}}
	}
	return packagedomain.ReadinessQuestion{ID: "customer_package_safe_to_share", Question: "Is a customer package available for review?", Answer: "No customer package was evaluated by this release readiness report.", Status: "limited", KnownLimitations: []string{"Package shareability is evaluated when a scoped customer package is generated."}}
}

func readinessGapQuestion(missingEvidence, failedPolicies []string) packagedomain.ReadinessQuestion {
	if len(missingEvidence) == 0 && len(failedPolicies) == 0 {
		return packagedomain.ReadinessQuestion{ID: "remaining_gaps", Question: "What gaps remain?", Answer: "No blocking readiness gaps are recorded by the current policy checks.", Status: "passed"}
	}
	status := "failed_policy"
	if len(failedPolicies) == 0 {
		status = "missing_evidence"
	}
	return packagedomain.ReadinessQuestion{ID: "remaining_gaps", Question: "What gaps remain?", Answer: "The report lists missing evidence and failed policy checks that should be reviewed.", Status: status, MissingEvidence: append([]string(nil), missingEvidence...), FailedPolicies: append([]string(nil), failedPolicies...)}
}

func sortedUniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
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

func cloneReadinessReportSnapshot(value ReadinessReportSnapshot) ReadinessReportSnapshot {
	value.Checks = clonePolicyCheckSnapshots(value.Checks)
	value.BlockingFindings = cloneBlockingFindings(value.BlockingFindings)
	value.AcceptedExceptions = cloneAcceptedExceptions(value.AcceptedExceptions)
	return value
}

func clonePolicyCheckSnapshots(values []packagedomain.PolicyCheckSnapshot) []packagedomain.PolicyCheckSnapshot {
	result := append([]packagedomain.PolicyCheckSnapshot(nil), values...)
	for index := range result {
		result[index].Missing = append([]string(nil), result[index].Missing...)
	}
	return result
}

func cloneBlockingFindings(values []packagedomain.BlockingFinding) []packagedomain.BlockingFinding {
	return append([]packagedomain.BlockingFinding(nil), values...)
}

func cloneAcceptedExceptions(values []packagedomain.AcceptedExceptionSnapshot) []packagedomain.AcceptedExceptionSnapshot {
	result := append([]packagedomain.AcceptedExceptionSnapshot(nil), values...)
	for index := range result {
		if result[index].ApprovedAt != nil {
			approvedAt := *result[index].ApprovedAt
			result[index].ApprovedAt = &approvedAt
		}
	}
	return result
}
