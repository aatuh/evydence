package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func mapReleaseReadinessReportQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrReleaseReadinessValidation):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrReleaseReadinessNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrReleaseReadinessProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

func releaseReadinessReportFromQuery(value packagedomain.ReleaseReadinessReport) domain.ReleaseReadinessReport {
	checks := make([]domain.PolicyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, domain.PolicyCheck{Name: check.Name, Result: check.Result, Severity: check.Severity, Missing: check.Missing, Explanation: check.Explanation, Remediation: check.Remediation})
	}
	sections := make([]domain.ReadinessSection, 0, len(value.Sections))
	for _, section := range value.Sections {
		questions := make([]domain.ReadinessQuestion, 0, len(section.Questions))
		for _, question := range section.Questions {
			questions = append(questions, domain.ReadinessQuestion{ID: question.ID, Question: question.Question, Answer: question.Answer, Status: question.Status, Evidence: question.Evidence, Checks: question.Checks, MissingEvidence: question.MissingEvidence, FailedPolicies: question.FailedPolicies, KnownLimitations: question.KnownLimitations})
		}
		sections = append(sections, domain.ReadinessSection{ID: section.ID, Title: section.Title, Status: section.Status, Summary: section.Summary, Questions: questions})
	}
	findings := make([]domain.BlockingFinding, 0, len(value.BlockingFindings))
	for _, finding := range value.BlockingFindings {
		findings = append(findings, domain.BlockingFinding{FindingID: finding.FindingID, ScanID: finding.ScanID, ReleaseID: finding.ReleaseID, Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity, State: finding.State})
	}
	return domain.ReleaseReadinessReport{
		ReportType: value.ReportType, TemplateVersion: value.TemplateVersion, ReleaseID: value.ReleaseID, Result: value.Result, PolicySet: value.PolicySet,
		Summary: domain.ReadinessSummary{Headline: value.Summary.Headline, Result: value.Summary.Result, HumanSummary: value.Summary.HumanSummary, PolicySet: value.Summary.PolicySet},
		Checks:  checks, Sections: sections, BlockingFindings: findings, AcceptedExceptions: controlReportExceptionsFromQuery(value.AcceptedExceptions),
		Gaps: value.Gaps, MissingEvidence: value.MissingEvidence, FailedPolicies: value.FailedPolicies, KnownLimitations: value.KnownLimitations,
		NonClaims: value.NonClaims, Assumptions: value.Assumptions, Limitations: value.Limitations, Metadata: value.Metadata, GeneratedAt: value.GeneratedAt,
	}
}
