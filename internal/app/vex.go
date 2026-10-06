package app

import (
	"bytes"
	"context"
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

type CreateExceptionInput struct {
	ReleaseID string
	FindingID string
	ControlID string
	Reason    string
	Owner     string
	ExpiresAt time.Time
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

func (l *Ledger) PreviewVEXImport(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXImportPreview, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if !ValidPayloadSize(int64(len(raw)), EvidenceDocumentLimit) {
		return domain.VEXImportPreview{}, ErrValidation
	}
	doc, err := parseOpenVEX(raw)
	if err != nil {
		return domain.VEXImportPreview{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
	if releaseID == "" {
		return domain.VEXImportPreview{}, ErrValidation
	}
	statusSummary := map[string]int{}
	for _, statement := range doc.Statements {
		statusSummary[statement.Status]++
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if err := l.ensureScopeLocked(actor.TenantID, "", "", releaseID); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if artifactID != "" {
		artifact, ok := l.artifacts[artifactID]
		if !ok || artifact.TenantID != actor.TenantID {
			return domain.VEXImportPreview{}, ErrNotFound
		}
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: releaseID}); err != nil {
		return domain.VEXImportPreview{}, err
	}
	created, superseded, warnings, mappingFailures := l.previewOpenVEXDecisionEffectsLocked(actor.TenantID, releaseID, doc.Statements)
	warnings = append(append([]string{}, doc.Warnings...), warnings...)
	return domain.VEXImportPreview{
		TenantID:                actor.TenantID,
		ReleaseID:               releaseID,
		ArtifactID:              artifactID,
		Format:                  "openvex",
		ParserVersion:           ParserVersionOpenVEXJSON,
		Advisory:                true,
		StatementCount:          len(doc.Statements),
		StatusSummary:           cloneIntMap(statusSummary),
		DecisionsWouldCreate:    created,
		DecisionsWouldSupersede: superseded,
		Warnings:                warnings,
		MappingFailures:         mappingFailures,
		Assumptions:             vexImportPreviewAssumptions(),
		Limitations:             vexImportPreviewLimitations(),
		SchemaVersion:           domain.VEXImportPreviewSchemaVersion,
		GeneratedAt:             l.now(),
	}, nil
}

func (l *Ledger) GetVEXImportReport(ctx context.Context, actor domain.Actor, vexID string) (domain.VEXImportReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXImportReport{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXImportReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VEXImportReport{}, err
	}
	vex, ok := l.vexDocuments[strings.TrimSpace(vexID)]
	if !ok || vex.TenantID != actor.TenantID {
		return domain.VEXImportReport{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: vex.ReleaseID}); err != nil {
		return domain.VEXImportReport{}, err
	}
	for _, report := range l.vexImportReports {
		if report.TenantID == actor.TenantID && report.VEXDocumentID == vex.ID {
			return report, nil
		}
	}
	return domain.VEXImportReport{}, ErrNotFound
}

func (l *Ledger) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (domain.VEXDocument, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXDocument{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXDocument{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VEXDocument{}, err
	}
	vex, ok := l.vexDocuments[strings.TrimSpace(id)]
	if !ok || vex.TenantID != actor.TenantID {
		return domain.VEXDocument{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: vex.ReleaseID}); err != nil {
		return domain.VEXDocument{}, err
	}
	return vex, nil
}

func customerDecisionSummary(decision domain.VulnerabilityDecision) domain.VulnerabilityDecisionCustomerSummary {
	return domain.VulnerabilityDecisionCustomerSummary{
		ID:                decision.ID,
		FindingID:         decision.FindingID,
		ScanID:            decision.ScanID,
		ReleaseID:         decision.ReleaseID,
		Vulnerability:     decision.Vulnerability,
		Component:         decision.Component,
		SBOMID:            decision.SBOMID,
		SBOMComponentPURL: decision.SBOMComponentPURL,
		SBOMComponentName: decision.SBOMComponentName,
		Status:            decision.Status,
		Justification:     decision.Justification,
		ImpactStatement:   decision.ImpactStatement,
		ActionStatement:   decision.ActionStatement,
		Source:            decision.Source,
		EvidenceID:        decision.EvidenceID,
		EvidenceIDs:       append([]string(nil), decision.EvidenceIDs...),
		SupportingRefs:    cloneSubjectRefs(decision.SupportingRefs),
		VEXDocumentID:     decision.VEXDocumentID,
		ReviewedAt:        cloneTimePtr(decision.ReviewedAt),
		ReviewDueAt:       cloneTimePtr(decision.ReviewDueAt),
		CreatedAt:         decision.CreatedAt,
	}
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

type matchedFinding struct {
	scan    domain.VulnerabilityScan
	finding domain.VulnerabilityFinding
}

func (l *Ledger) findMatchingFindingsLocked(tenantID, releaseID string, statement openVEXStatement) ([]matchedFinding, bool) {
	out := []matchedFinding{}
	products := openVEXProductIDs(statement.Products)
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		for _, finding := range scan.Findings {
			if finding.Vulnerability != statement.Vulnerability.Name {
				continue
			}
			if len(products) > 0 && finding.Component != "" {
				if _, ok := products[finding.Component]; !ok {
					continue
				}
			}
			out = append(out, matchedFinding{scan: scan, finding: finding})
		}
	}
	return unambiguousVEXMatches(out, products)
}

func (l *Ledger) previewOpenVEXDecisionEffectsLocked(tenantID, releaseID string, statements []openVEXStatement) (int, int, []string, []domain.VEXImportIssue) {
	created, superseded := 0, 0
	mappingFailures := []domain.VEXImportIssue{}
	warnings := []string{}
	createdForFinding := map[string]struct{}{}
	duplicateWarningAdded := false
	for index, statement := range statements {
		matches, ambiguous := l.findMatchingFindingsLocked(tenantID, releaseID, statement)
		if ambiguous {
			mappingFailures = append(mappingFailures, vexImportIssue(index+1, "ambiguous_finding", "Multiple plausible findings matched this VEX statement; no decision would be applied."))
			continue
		}
		if len(matches) == 0 {
			mappingFailures = append(mappingFailures, vexImportIssue(index+1, "finding_not_found", "No matching vulnerability scan finding was found for this VEX statement."))
		}
		added, replaced, duplicate := l.previewDecisionEffectsForMatchesLocked(tenantID, matches, createdForFinding)
		created += added
		superseded += replaced
		if duplicate && !duplicateWarningAdded {
			warnings = append(warnings, "Duplicate VEX statements for an already mapped finding were ignored.")
			duplicateWarningAdded = true
		}
	}
	return created, superseded, warnings, mappingFailures
}

func unambiguousVEXMatches(matches []matchedFinding, productRefs map[string]struct{}) ([]matchedFinding, bool) {
	if len(matches) < 2 {
		return matches, false
	}
	if len(productRefs) == 0 || len(matches) > len(productRefs) {
		return nil, true
	}
	seenComponents := map[string]struct{}{}
	for _, match := range matches {
		component := strings.TrimSpace(match.finding.Component)
		if component == "" {
			return nil, true
		}
		if _, allowed := productRefs[component]; !allowed {
			return nil, true
		}
		if _, duplicate := seenComponents[component]; duplicate {
			return nil, true
		}
		seenComponents[component] = struct{}{}
	}
	return matches, false
}

func (l *Ledger) previewDecisionEffectsForMatchesLocked(tenantID string, matches []matchedFinding, createdForFinding map[string]struct{}) (int, int, bool) {
	created, superseded := 0, 0
	duplicate := false
	for _, matched := range matches {
		if _, seen := createdForFinding[matched.finding.ID]; seen {
			duplicate = true
			continue
		}
		createdForFinding[matched.finding.ID] = struct{}{}
		created++
		if _, ok := l.latestDecisionForFindingLocked(tenantID, matched.finding.ID); ok {
			superseded++
		}
	}
	return created, superseded, duplicate
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
