package app

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

const (
	decisionStatusAffected           = "affected"
	decisionStatusNotAffected        = "not_affected"
	decisionStatusFixed              = "fixed"
	decisionStatusUnderInvestigation = "under_investigation"
)

type CreateVulnerabilityDecisionInput struct {
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	CustomerVisible bool
	InternalNotes   string
	EvidenceIDs     []string
	SupportingRefs  []domain.SubjectRef
	VEXDocumentID   string
	ReviewedAt      *time.Time
	ReviewDueAt     *time.Time
}

type ListVulnerabilityDecisionsInput struct {
	ProductID     string
	ReleaseID     string
	Vulnerability string
	Component     string
	Status        string
	Active        *bool
}

type openVEXDocument struct {
	Context    any                `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    any                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
	Warnings   []string           `json:"-"`
}

type openVEXStatement struct {
	Vulnerability   openVEXVulnerability `json:"vulnerability"`
	Products        []openVEXProduct     `json:"products"`
	Status          string               `json:"status"`
	Justification   string               `json:"justification"`
	ImpactStatement string               `json:"impact_statement"`
	ActionStatement string               `json:"action_statement"`
}

type openVEXVulnerability struct {
	Name string `json:"name"`
}

type openVEXProduct struct {
	ID            string           `json:"@id"`
	Subcomponents []openVEXProduct `json:"subcomponents,omitempty"`
}

func (l *Ledger) activeDecisionCountForReleaseLocked(tenantID, releaseID string) int {
	count := 0
	for _, decision := range l.decisions {
		if decision.TenantID == tenantID && decision.ReleaseID == releaseID && decision.SupersededBy == "" {
			count++
		}
	}
	return count
}

func (l *Ledger) hasActiveCustomerPackageLocked(tenantID, releaseID string) bool {
	for _, pkg := range l.customerPackages {
		if pkg.TenantID == tenantID && pkg.ReleaseID == releaseID && pkg.State == "generated" && pkg.ExpiresAt.After(l.now()) {
			return true
		}
	}
	return false
}

func redactionProfileExcludesPackageSensitiveFields(profile domain.RedactionProfile) bool {
	required := map[string]struct{}{"payload_ref": {}, "object_key": {}, "private_key": {}, "token": {}, "secret": {}, "internal_notes": {}}
	for _, field := range profile.ExcludedFields {
		delete(required, strings.ToLower(strings.TrimSpace(field)))
	}
	return len(required) == 0
}

func parseOpenVEX(raw []byte) (openVEXDocument, error) {
	return parseOpenVEXReader(bytes.NewReader(raw))
}

func parseOpenVEXReader(reader io.Reader) (openVEXDocument, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, EvidenceDocumentLimit+1))
	if err != nil || int64(len(raw)) > EvidenceDocumentLimit {
		return openVEXDocument{}, vexValidationError("openvex JSON is malformed")
	}
	parsed, err := vexparser.ParseOpenVEX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
	if err != nil {
		return openVEXDocument{}, vexValidationError("openvex JSON is malformed or violates required OpenVEX fields")
	}
	doc := openVEXDocument{Author: parsed.Author, Version: parsed.Version, Warnings: parsed.Warnings}
	for _, statement := range parsed.Statements {
		products := make([]openVEXProduct, 0, len(statement.Products))
		for _, product := range statement.Products {
			products = append(products, openVEXProduct{ID: product})
		}
		doc.Statements = append(doc.Statements, openVEXStatement{Vulnerability: openVEXVulnerability{Name: statement.Vulnerability}, Products: products, Status: statement.Status, Justification: statement.Justification, ImpactStatement: statement.ImpactStatement, ActionStatement: statement.ActionStatement})
	}
	return doc, nil
}

func vexValidationError(detail string) error {
	return fmt.Errorf("%s: %w", detail, ErrValidation)
}

func validDecisionStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation:
		return true
	default:
		return false
	}
}

func openVEXProductIDs(products []openVEXProduct) map[string]struct{} {
	out := map[string]struct{}{}
	var walk func([]openVEXProduct)
	walk = func(items []openVEXProduct) {
		for _, item := range items {
			if id := strings.TrimSpace(item.ID); id != "" {
				out[id] = struct{}{}
			}
			walk(item.Subcomponents)
		}
	}
	walk(products)
	return out
}

func (l *Ledger) decisionSBOMContextLocked(tenantID, releaseID, findingComponent string) (string, string, string) {
	findingComponent = strings.TrimSpace(findingComponent)
	if releaseID == "" || findingComponent == "" {
		return "", "", ""
	}
	sboms := make([]domain.SBOM, 0, len(l.sboms))
	for _, sbom := range l.sboms {
		if sbom.TenantID == tenantID && sbom.ReleaseID == releaseID {
			sboms = append(sboms, sbom)
		}
	}
	sort.Slice(sboms, func(i, j int) bool {
		if sboms[i].CreatedAt.Equal(sboms[j].CreatedAt) {
			return sboms[i].ID < sboms[j].ID
		}
		return sboms[i].CreatedAt.Before(sboms[j].CreatedAt)
	})
	for _, sbom := range sboms {
		for _, component := range sbom.Components {
			if strings.TrimSpace(component.PURL) != "" && strings.TrimSpace(component.PURL) == findingComponent {
				return sbom.ID, strings.TrimSpace(component.PURL), strings.TrimSpace(component.Name)
			}
		}
	}
	for _, sbom := range sboms {
		for _, component := range sbom.Components {
			name := strings.TrimSpace(component.Name)
			version := strings.TrimSpace(component.Version)
			if name == findingComponent || (version != "" && name+"@"+version == findingComponent) {
				return sbom.ID, strings.TrimSpace(component.PURL), name
			}
		}
	}
	return "", "", ""
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := value.UTC()
	return &clone
}

func (l *Ledger) decisionSupportingRefInScopeLocked(tenantID, productID, releaseID string, ref domain.SubjectRef) bool {
	switch ref.Type {
	case "approval":
		approval, ok := l.approvals[ref.ID]
		return ok && approval.TenantID == tenantID && l.approvalSupportsReleaseLocked(tenantID, productID, releaseID, approval)
	case "exception":
		exception, ok := l.exceptions[ref.ID]
		return ok && exception.TenantID == tenantID && exception.ReleaseID == releaseID
	case "waiver":
		waiver, ok := l.waivers[ref.ID]
		return ok && waiver.TenantID == tenantID && waiverBelongsToPackage(waiver, productID, releaseID)
	case "release_bundle":
		bundle, ok := l.bundles[ref.ID]
		return ok && bundle.TenantID == tenantID && bundle.ReleaseID == releaseID
	case "incident":
		incident, ok := l.incidents[ref.ID]
		return ok && incident.TenantID == tenantID && incident.ReleaseID == releaseID
	case "remediation_task":
		task, ok := l.tasks[ref.ID]
		if !ok || task.TenantID != tenantID {
			return false
		}
		if task.ReleaseID == releaseID {
			return true
		}
		if task.IncidentID != "" {
			incident, ok := l.incidents[task.IncidentID]
			return ok && incident.TenantID == tenantID && incident.ReleaseID == releaseID
		}
		return false
	default:
		return false
	}
}

func (l *Ledger) approvalSupportsReleaseLocked(tenantID, productID, releaseID string, approval domain.ApprovalRecord) bool {
	switch approval.SubjectType {
	case "release":
		return approval.SubjectID == releaseID
	case "waiver":
		waiver, ok := l.waivers[approval.SubjectID]
		return ok && waiver.TenantID == tenantID && waiverBelongsToPackage(waiver, productID, releaseID)
	case "customer_package":
		pkg, ok := l.customerPackages[approval.SubjectID]
		return ok && pkg.TenantID == tenantID && pkg.ProductID == productID && pkg.ReleaseID == releaseID
	case "contract_diff":
		diff, ok := l.contractDiffs[approval.SubjectID]
		return ok && diff.TenantID == tenantID && diff.ProductID == productID && diff.ReleaseID == releaseID
	case "security_review":
		doc, ok := l.manualDocs[approval.SubjectID]
		return ok && doc.TenantID == tenantID && doc.ProductID == productID && doc.ReleaseID == releaseID && doc.DocumentType == "security_review"
	default:
		return false
	}
}

func cloneSubjectRefs(refs []domain.SubjectRef) []domain.SubjectRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]domain.SubjectRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, domain.SubjectRef{Type: strings.TrimSpace(ref.Type), ID: strings.TrimSpace(ref.ID), Digest: strings.TrimSpace(ref.Digest)})
	}
	return out
}

func decisionEvidenceIDs(primary string, extra []string) []string {
	ids := append([]string(nil), extra...)
	if strings.TrimSpace(primary) != "" {
		ids = append(ids, strings.TrimSpace(primary))
	}
	return sortedUniqueNonEmptyStrings(ids)
}

func vexImportIssue(statementIndex int, code, detail string) domain.VEXImportIssue {
	return domain.VEXImportIssue{StatementIndex: statementIndex, Code: code, Detail: detail}
}

func vexImportPreviewAssumptions() []string {
	return evidencedomain.VEXPreviewAssumptions()
}

func vexImportPreviewLimitations() []string {
	return evidencedomain.VEXPreviewLimitations()
}

func sortedUniqueNonEmptyStrings(in []string) []string {
	set := map[string]struct{}{}
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (l *Ledger) findFindingLocked(tenantID, findingID string) (domain.VulnerabilityScan, domain.VulnerabilityFinding, bool) {
	for _, scan := range l.scans {
		if scan.TenantID != tenantID {
			continue
		}
		for _, finding := range scan.Findings {
			if finding.ID == findingID {
				return scan, finding, true
			}
		}
	}
	return domain.VulnerabilityScan{}, domain.VulnerabilityFinding{}, false
}

func (l *Ledger) latestDecisionForFindingLocked(tenantID, findingID string) (domain.VulnerabilityDecision, bool) {
	var latest domain.VulnerabilityDecision
	for _, decision := range l.decisions {
		if decision.TenantID != tenantID || decision.FindingID != findingID || decision.SupersededBy != "" {
			continue
		}
		if latest.ID == "" || decision.CreatedAt.After(latest.CreatedAt) {
			latest = decision
		}
	}
	return latest, latest.ID != ""
}

func (l *Ledger) findingHandledLocked(tenantID string, scan domain.VulnerabilityScan, finding domain.VulnerabilityFinding) bool {
	if decision, ok := l.latestDecisionForFindingLocked(tenantID, finding.ID); ok {
		if decision.Status == decisionStatusNotAffected || decision.Status == decisionStatusFixed {
			return true
		}
	}
	for _, exception := range l.exceptions {
		if exception.TenantID != tenantID || exception.ReleaseID != scan.ReleaseID || !exception.Approved || !exception.ExpiresAt.After(l.now()) {
			continue
		}
		if exception.FindingID == "" || exception.FindingID == finding.ID {
			return true
		}
	}
	return false
}

func (l *Ledger) unhandledCriticalFindingsLocked(tenantID, releaseID string) []domain.BlockingFinding {
	return l.unhandledFindingsBySeverityLocked(tenantID, releaseID, "critical")
}

func (l *Ledger) unhandledFindingsBySeverityLocked(tenantID, releaseID string, severities ...string) []domain.BlockingFinding {
	allowed := map[string]struct{}{}
	for _, severity := range severities {
		allowed[strings.ToLower(strings.TrimSpace(severity))] = struct{}{}
	}
	blocking := []domain.BlockingFinding{}
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		for _, finding := range scan.Findings {
			if _, ok := allowed[strings.ToLower(finding.Severity)]; !ok || strings.ToLower(nonEmpty(finding.State, "open")) != "open" {
				continue
			}
			if l.findingHandledLocked(tenantID, scan, finding) {
				continue
			}
			blocking = append(blocking, domain.BlockingFinding{
				FindingID:     finding.ID,
				ScanID:        scan.ID,
				ReleaseID:     scan.ReleaseID,
				Vulnerability: finding.Vulnerability,
				Component:     finding.Component,
				Severity:      finding.Severity,
				State:         finding.State,
			})
		}
	}
	sort.Slice(blocking, func(i, j int) bool { return blocking[i].FindingID < blocking[j].FindingID })
	return blocking
}

func (l *Ledger) acceptedExceptionsForReleaseLocked(tenantID, releaseID string) []domain.Exception {
	out := []domain.Exception{}
	for _, exception := range l.exceptions {
		if exception.TenantID == tenantID && exception.ReleaseID == releaseID && exception.Approved && exception.ExpiresAt.After(l.now()) {
			out = append(out, exception)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
