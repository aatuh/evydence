package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical methods are package-local test oracles only.

func (l *Ledger) ControlCoverageReport(ctx context.Context, actor domain.Actor, in ControlCoverageReportInput) (domain.ControlCoverageReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.ControlCoverageReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.ControlCoverageReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.ControlCoverageReport{}, err
	}
	report, err := l.controlCoverageReportLocked(actor.TenantID, in)
	if err != nil {
		return domain.ControlCoverageReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: report.ProductID, ReleaseID: report.ReleaseID}); err != nil {
		return domain.ControlCoverageReport{}, err
	}
	return report, nil
}

func (l *Ledger) CRAReadinessReport(ctx context.Context, actor domain.Actor, in CRAReadinessReportInput) (domain.CRAReadinessReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	if strings.TrimSpace(in.ProductID) == "" {
		return domain.CRAReadinessReport{}, ErrValidation
	}
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	return l.craReadinessReportLocked(actor.TenantID, in.ProductID, in.ReleaseID)
}

func (l *Ledger) CRAVulnerabilityHandlingReport(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.CRAVulnerabilityHandlingReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.CRAVulnerabilityHandlingReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.CRAVulnerabilityHandlingReport{}, err
	}
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	if productID == "" || releaseID == "" {
		return domain.CRAVulnerabilityHandlingReport{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.CRAVulnerabilityHandlingReport{}, err
	}
	if err := l.ensureScopeLocked(actor.TenantID, productID, "", releaseID); err != nil {
		return domain.CRAVulnerabilityHandlingReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: productID, ReleaseID: releaseID}); err != nil {
		return domain.CRAVulnerabilityHandlingReport{}, err
	}
	summary := map[string]int{
		"findings_total":            0,
		"open_critical_total":       0,
		"decisions_total":           0,
		"approved_exceptions_total": 0,
	}
	evidenceIDs := []string{}
	for _, scan := range l.scans {
		if scan.TenantID != actor.TenantID || scan.ReleaseID != releaseID {
			continue
		}
		evidenceIDs = append(evidenceIDs, scan.EvidenceID)
		summary["findings_total"] += len(scan.Findings)
		for _, finding := range scan.Findings {
			if strings.EqualFold(finding.Severity, "critical") && strings.EqualFold(finding.State, "open") {
				summary["open_critical_total"]++
			}
		}
	}
	decisions := []domain.VulnerabilityDecisionCustomerSummary{}
	for _, decision := range l.decisions {
		if decision.TenantID != actor.TenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" {
			continue
		}
		decisions = append(decisions, customerDecisionSummary(decision))
		evidenceIDs = append(evidenceIDs, decisionEvidenceIDs(decision.EvidenceID, decision.EvidenceIDs)...)
		if decision.VEXDocumentID != "" {
			if vex, ok := l.vexDocuments[decision.VEXDocumentID]; ok && vex.TenantID == actor.TenantID {
				evidenceIDs = append(evidenceIDs, vex.EvidenceID)
			}
		}
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].ID < decisions[j].ID })
	summary["decisions_total"] = len(decisions)
	exceptions := []domain.Exception{}
	now := l.now()
	for _, exception := range l.exceptions {
		if exception.TenantID == actor.TenantID && exception.ReleaseID == releaseID && exception.Approved && exception.ExpiresAt.After(now) {
			exceptions = append(exceptions, exception)
		}
	}
	sort.Slice(exceptions, func(i, j int) bool { return exceptions[i].ID < exceptions[j].ID })
	summary["approved_exceptions_total"] = len(exceptions)
	evidenceIDs = sortedUniqueNonEmptyStrings(evidenceIDs)
	summary["evidence_total"] = len(evidenceIDs)
	return domain.CRAVulnerabilityHandlingReport{
		ReportType:         "cra_vulnerability_handling",
		TemplateVersion:    "cra-vulnerability-handling.v1.0.0",
		ProductID:          productID,
		ReleaseID:          releaseID,
		Summary:            summary,
		Decisions:          decisions,
		AcceptedExceptions: exceptions,
		EvidenceIDs:        evidenceIDs,
		Assumptions:        []string{"This report summarizes vulnerability handling records for CRA readiness review using evidence stored in this tenant."},
		Limitations:        []string{"Report contents do not prove legal compliance, certification, complete vulnerability detection, scanner authority, or release security status."},
		GeneratedAt:        l.now(),
	}, nil
}
