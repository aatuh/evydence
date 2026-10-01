package query

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var (
	ErrSecurityUpdateValidation = errors.New("invalid security update evidence query")
	ErrSecurityUpdateNotFound   = errors.New("security update release not found")
	ErrSecurityUpdateProjection = errors.New("invalid security update evidence projection")
	ErrSecurityUpdateCapacity   = errors.New("security update evidence report exceeds the bounded result size")
)

// SecurityUpdateSnapshot contains only report-safe records for one verified
// release, read from one committed database view. Internal decision notes are
// never part of the projection.
type SecurityUpdateSnapshot struct {
	TenantID, ProductID, ReleaseID string
	ScanEvidenceIDs                []string
	Decisions                      []riskdomain.VulnerabilityDecision
	VEXEvidenceIDs                 map[string]string
	Incidents                      []operationsdomain.Incident
	Tasks                          []operationsdomain.RemediationTask
}

type SecurityUpdateReader interface {
	ReadSecurityUpdateSnapshot(context.Context, string, string, string) (SecurityUpdateSnapshot, error)
}

type SecurityUpdateEvidence struct {
	reader SecurityUpdateReader
	now    func() time.Time
}

func NewSecurityUpdateEvidence(reader SecurityUpdateReader, now func() time.Time) (*SecurityUpdateEvidence, error) {
	if reader == nil || now == nil {
		return nil, ErrSecurityUpdateValidation
	}
	return &SecurityUpdateEvidence{reader: reader, now: now}, nil
}

func (s *SecurityUpdateEvidence) Report(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.SecurityUpdateEvidenceReport, error) {
	var empty packagedomain.SecurityUpdateEvidenceReport
	if s == nil || ctx == nil {
		return empty, ErrSecurityUpdateValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope("report:read") && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	if productID == "" || releaseID == "" {
		return empty, ErrSecurityUpdateValidation
	}
	if !securityUpdateAllowed(actor, productID, releaseID) {
		return empty, application.ErrForbidden
	}
	snapshot, err := s.reader.ReadSecurityUpdateSnapshot(ctx, actor.TenantID, productID, releaseID)
	if err != nil {
		return empty, err
	}
	if snapshot.TenantID != actor.TenantID || snapshot.ProductID != productID || snapshot.ReleaseID != releaseID {
		return empty, ErrSecurityUpdateNotFound
	}
	if len(snapshot.ScanEvidenceIDs)+len(snapshot.Decisions)+len(snapshot.Incidents)+len(snapshot.Tasks) > MaxSecurityUpdateEntries {
		return empty, ErrSecurityUpdateCapacity
	}
	evidenceIDs := append([]string(nil), snapshot.ScanEvidenceIDs...)
	decisions := make([]packagedomain.VulnerabilityDecisionSnapshot, 0, len(snapshot.Decisions))
	for _, decision := range snapshot.Decisions {
		if decision.ID == "" || decision.TenantID != actor.TenantID || decision.ReleaseID != releaseID || decision.Status.String() != "fixed" || decision.SupersededBy != "" || decision.InternalNotes != "" || decision.FindingID == "" || decision.ScanID == "" {
			return empty, ErrSecurityUpdateProjection
		}
		customer := riskdomain.CustomerDecisionSummary(decision)
		refs := make([]packagedomain.SupportingReference, 0, len(customer.SupportingRefs))
		for _, ref := range customer.SupportingRefs {
			refs = append(refs, packagedomain.SupportingReference{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
		}
		decisions = append(decisions, packagedomain.VulnerabilityDecisionSnapshot{
			ID: customer.ID, FindingID: customer.FindingID, ScanID: customer.ScanID, ReleaseID: customer.ReleaseID,
			Vulnerability: customer.Vulnerability, Component: customer.Component, SBOMID: customer.SBOMID,
			SBOMComponentPURL: customer.SBOMComponentPURL, SBOMComponentName: customer.SBOMComponentName,
			Status: customer.Status, Justification: customer.Justification, ImpactStatement: customer.ImpactStatement,
			ActionStatement: customer.ActionStatement, Source: customer.Source, EvidenceID: customer.EvidenceID,
			EvidenceIDs: customer.EvidenceIDs, SupportingRefs: refs, VEXDocumentID: customer.VEXDocumentID,
			ReviewedAt: customer.ReviewedAt, ReviewDueAt: customer.ReviewDueAt, CreatedAt: customer.CreatedAt,
		})
		evidenceIDs = append(evidenceIDs, decision.EvidenceID)
		evidenceIDs = append(evidenceIDs, decision.EvidenceIDs...)
		if decision.VEXDocumentID != "" {
			vexEvidenceID := snapshot.VEXEvidenceIDs[decision.VEXDocumentID]
			if vexEvidenceID == "" {
				return empty, ErrSecurityUpdateProjection
			}
			evidenceIDs = append(evidenceIDs, vexEvidenceID)
		}
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].ID < decisions[j].ID })
	incidents := make([]packagedomain.IncidentSnapshot, 0, len(snapshot.Incidents))
	incidentIDs := make(map[string]struct{}, len(snapshot.Incidents))
	for _, incident := range snapshot.Incidents {
		if incident.ID == "" || incident.TenantID != actor.TenantID || incident.ProductID != productID || incident.ReleaseID != releaseID || incident.Status.IsZero() {
			return empty, ErrSecurityUpdateProjection
		}
		incidentIDs[incident.ID] = struct{}{}
		incidents = append(incidents, packagedomain.IncidentSnapshot{
			ID: incident.ID, TenantID: incident.TenantID, ProductID: incident.ProductID, ReleaseID: incident.ReleaseID,
			Title: incident.Title, Severity: incident.Severity, Status: incident.Status.String(), OpenedAt: incident.OpenedAt,
			ClosedAt: incident.ClosedAt, SchemaVersion: incident.SchemaVersion, CreatedAt: incident.CreatedAt,
		})
	}
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })
	tasks := make([]packagedomain.RemediationTaskSnapshot, 0, len(snapshot.Tasks))
	for _, task := range snapshot.Tasks {
		_, incidentMatches := incidentIDs[task.IncidentID]
		if task.ID == "" || task.TenantID != actor.TenantID || task.ReleaseID != "" && task.ReleaseID != releaseID || task.ReleaseID == "" && !incidentMatches || task.IncidentID != "" && !incidentMatches {
			return empty, ErrSecurityUpdateProjection
		}
		tasks = append(tasks, packagedomain.RemediationTaskSnapshot{
			ID: task.ID, TenantID: task.TenantID, IncidentID: task.IncidentID, ReleaseID: task.ReleaseID,
			Title: task.Title, Owner: task.Owner, Status: task.Status, DueAt: task.DueAt,
			EvidenceID: task.EvidenceID, SchemaVersion: task.SchemaVersion, CreatedAt: task.CreatedAt,
		})
		evidenceIDs = append(evidenceIDs, task.EvidenceID)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	evidenceIDs = sortedSecurityUpdateEvidenceIDs(evidenceIDs)
	if len(evidenceIDs) > MaxSecurityUpdateEntries {
		return empty, ErrSecurityUpdateCapacity
	}
	return packagedomain.SecurityUpdateEvidenceReport{
		ReportType: "security_update_evidence", TemplateVersion: "security-update-evidence.v1.0.0",
		ProductID: productID, ReleaseID: releaseID,
		Summary: map[string]int{
			"fixed_decisions_total": len(decisions), "incidents_total": len(incidents),
			"remediation_tasks_total": len(tasks), "linked_evidence_total": len(evidenceIDs),
			"security_update_subjects": len(decisions) + len(incidents) + len(tasks),
		},
		FixedDecisions: decisions, Incidents: incidents, RemediationTasks: tasks, EvidenceIDs: evidenceIDs,
		Assumptions: []string{"This report summarizes recorded release evidence that may support security update review."},
		Limitations: []string{"Security update evidence is scoped to records in this Evydence tenant and does not prove legal sufficiency, customer notification completeness, or release security status."},
		GeneratedAt: s.now(),
	}, nil
}

// MaxSecurityUpdateEntries caps complete, non-paginated report projections.
// Readers fetch one extra row to detect overflow without truncating evidence.
const MaxSecurityUpdateEntries = 4096

func securityUpdateAllowed(actor identitydomain.Actor, productID, releaseID string) bool {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		allowed := false
		for _, scope := range grant.Scopes {
			if scope == "report:read" || scope == "admin" || scope == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true
			}
		case "product":
			if grant.ResourceID == productID {
				return true
			}
		case "release":
			if grant.ResourceID == releaseID {
				return true
			}
		}
	}
	return false
}

func sortedSecurityUpdateEvidenceIDs(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
