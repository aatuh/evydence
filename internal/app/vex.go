package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

const (
	decisionStatusAffected           = "affected"
	decisionStatusNotAffected        = "not_affected"
	decisionStatusFixed              = "fixed"
	decisionStatusUnderInvestigation = "under_investigation"
)

var decisionStatusTransitions = map[string]map[string]struct{}{
	decisionStatusAffected:           decisionStatusSet(decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation),
	decisionStatusNotAffected:        decisionStatusSet(decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation),
	decisionStatusFixed:              decisionStatusSet(decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation),
	decisionStatusUnderInvestigation: decisionStatusSet(decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation),
}

type CreateVulnerabilityDecisionInput struct {
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	CustomerVisible bool
	InternalNotes   string
	EvidenceIDs     []string
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

func (s releaseEvidenceService) UploadVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.VEXDocument{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.VEXDocument{}, err
	}
	if len(raw) == 0 || len(raw) > 20<<20 {
		return domain.VEXDocument{}, ErrValidation
	}
	doc, err := parseOpenVEX(raw)
	if err != nil {
		return domain.VEXDocument{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
	if releaseID == "" {
		return domain.VEXDocument{}, ErrValidation
	}
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, "", "", releaseID); err != nil {
		l.mu.Unlock()
		return domain.VEXDocument{}, err
	}
	if artifactID != "" {
		artifact, ok := l.artifacts[artifactID]
		if !ok || artifact.TenantID != actor.TenantID {
			l.mu.Unlock()
			return domain.VEXDocument{}, ErrNotFound
		}
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: releaseID}); err != nil {
		l.mu.Unlock()
		return domain.VEXDocument{}, err
	}
	l.mu.Unlock()

	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "vex", "application/vnd.openvex+json", payloadHash, raw)
	if err != nil {
		return domain.VEXDocument{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID:        releaseID,
		Type:             "vex",
		Subtype:          "openvex",
		Title:            "OpenVEX document",
		SourceSystem:     "api",
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/vnd.openvex+json",
		PayloadSize:      int64(len(raw)),
		SubjectRefs:      subjectForArtifact(artifactID),
		Metadata: map[string]any{
			"format":          "openvex",
			"statement_count": len(doc.Statements),
		},
	})
	if err != nil {
		return domain.VEXDocument{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	statusSummary := map[string]int{}
	for _, statement := range doc.Statements {
		statusSummary[statement.Status]++
	}
	vex := domain.VEXDocument{
		ID:             newID("vex"),
		TenantID:       actor.TenantID,
		EvidenceID:     item.ID,
		ReleaseID:      releaseID,
		ArtifactID:     artifactID,
		Format:         "openvex",
		Author:         doc.Author,
		Version:        versionString(doc.Version),
		StatementCount: len(doc.Statements),
		StatusSummary:  statusSummary,
		SchemaVersion:  domain.VEXDocumentSchemaVersion,
		CreatedAt:      l.now(),
	}
	persistedVEX := vex
	chainAction := "vex.parsed"
	if l.workerOwnedParsers {
		persistedVEX.Author = ""
		persistedVEX.StatementCount = 0
		persistedVEX.StatusSummary = nil
		chainAction = "vex.accepted"
	}
	l.vexDocuments[vex.ID] = persistedVEX
	createdDecisions := 0
	supersededDecisions := 0
	mappingFailures := []domain.VEXImportIssue{}
	warnings := []string{}
	if !l.workerOwnedParsers {
		createdForFinding := map[string]struct{}{}
		duplicateWarningAdded := false
		for index, statement := range doc.Statements {
			matches := l.findMatchingFindingsLocked(actor.TenantID, releaseID, statement)
			if len(matches) == 0 {
				mappingFailures = append(mappingFailures, vexImportIssue(index+1, "finding_not_found", "No matching vulnerability scan finding was found for this VEX statement."))
			}
			for _, matched := range matches {
				if _, seen := createdForFinding[matched.finding.ID]; seen {
					if !duplicateWarningAdded {
						warnings = append(warnings, "Duplicate VEX statements for an already mapped finding were ignored.")
						duplicateWarningAdded = true
					}
					continue
				}
				createdForFinding[matched.finding.ID] = struct{}{}
				decision := l.createDecisionLocked(actor.TenantID, matched.scan, matched.finding, CreateVulnerabilityDecisionInput{
					Status:          statement.Status,
					Justification:   statement.Justification,
					ImpactStatement: statement.ImpactStatement,
					ActionStatement: statement.ActionStatement,
					CustomerVisible: strings.TrimSpace(statement.ImpactStatement) != "",
				}, "vex", actorID(actor), item.ID, vex.ID)
				l.decisions[decision.ID] = decision
				if decision.Supersedes != "" {
					supersededDecisions++
				}
				l.appendDecisionLifecycleAuditLocked(actor.TenantID, decision, matched.finding.ID, actorType(actor), actorID(actor), payloadHash)
				createdDecisions++
			}
		}
	} else {
		for index, statement := range doc.Statements {
			if len(l.findMatchingFindingsLocked(actor.TenantID, releaseID, statement)) == 0 {
				mappingFailures = append(mappingFailures, vexImportIssue(index+1, "finding_not_found", "No matching vulnerability scan finding was found for this VEX statement at upload time."))
			}
		}
	}
	if l.workerOwnedParsers {
		warnings = append(warnings, "Worker-owned parser side effects are enabled; decisions are created asynchronously after payload replay.")
	}
	report := domain.VEXImportReport{
		ID:                  newID("vexrep"),
		TenantID:            actor.TenantID,
		VEXDocumentID:       vex.ID,
		EvidenceID:          item.ID,
		ReleaseID:           releaseID,
		ArtifactID:          artifactID,
		ParserVersion:       ParserVersionOpenVEXJSON,
		Status:              ternary(l.workerOwnedParsers, "accepted", "parsed"),
		StatementCount:      len(doc.Statements),
		DecisionsCreated:    createdDecisions,
		DecisionsSuperseded: supersededDecisions,
		UnsupportedFields:   []string{},
		Warnings:            warnings,
		MappingFailures:     mappingFailures,
		SchemaVersion:       domain.VEXImportReportSchemaVersion,
		CreatedAt:           l.now(),
		UpdatedAt:           l.now(),
	}
	l.vexImportReports[report.ID] = report
	_, _ = l.appendChainLocked(actor.TenantID, chainAction, "vex_document", vex.ID, actorType(actor), actorID(actor), payloadHash, "")
	jobPayload := map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionOpenVEXJSON, "decisions_created": createdDecisions, "import_report_id": report.ID}
	if l.workerOwnedParsers {
		jobPayload["worker_create_decisions"] = true
		jobPayload["actor_type"] = actorType(actor)
		jobPayload["actor_id"] = actorID(actor)
		jobPayload["evidence_id"] = item.ID
	}
	job := l.newOutboxJob(actor.TenantID, "parse_vex", "vex_document", vex.ID, jobPayload)
	if err := l.persistReleaseLedgerWithOutboxLocked(ctx, job); err != nil {
		return domain.VEXDocument{}, err
	}
	return vex, nil
}

func (s releaseEvidenceService) GetVEXImportReport(ctx context.Context, actor domain.Actor, vexID string) (domain.VEXImportReport, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.VEXImportReport{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXImportReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
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

func (s releaseEvidenceService) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (domain.VEXDocument, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.VEXDocument{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXDocument{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	vex, ok := l.vexDocuments[strings.TrimSpace(id)]
	if !ok || vex.TenantID != actor.TenantID {
		return domain.VEXDocument{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: vex.ReleaseID}); err != nil {
		return domain.VEXDocument{}, err
	}
	return vex, nil
}

func (s releaseEvidenceService) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, findingID string, in CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	if !validDecisionStatus(in.Status) || strings.TrimSpace(in.Justification) == "" {
		return domain.VulnerabilityDecision{}, ErrValidation
	}
	if in.CustomerVisible && strings.TrimSpace(in.ImpactStatement) == "" {
		return domain.VulnerabilityDecision{}, ErrValidation
	}
	if len(strings.TrimSpace(in.InternalNotes)) > 8192 {
		return domain.VulnerabilityDecision{}, ErrValidation
	}
	if err := normalizeDecisionReviewTimes(&in, l.now()); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	scan, finding, ok := l.findFindingLocked(actor.TenantID, strings.TrimSpace(findingID))
	if !ok {
		return domain.VulnerabilityDecision{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: scan.ReleaseID}); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	if latest, ok := l.latestDecisionForFindingLocked(actor.TenantID, finding.ID); ok && !validDecisionTransition(latest.Status, strings.TrimSpace(in.Status)) {
		return domain.VulnerabilityDecision{}, ErrValidation
	}
	in.VEXDocumentID = strings.TrimSpace(in.VEXDocumentID)
	if in.VEXDocumentID != "" {
		vex, ok := l.vexDocuments[in.VEXDocumentID]
		if !ok || vex.TenantID != actor.TenantID || vex.ReleaseID != scan.ReleaseID {
			return domain.VulnerabilityDecision{}, ErrNotFound
		}
		in.VEXDocumentID = vex.ID
	}
	evidenceIDs, err := l.validateDecisionEvidenceLinksLocked(actor.TenantID, scan.ReleaseID, in.EvidenceIDs)
	if err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	in.EvidenceIDs = evidenceIDs
	decision := l.createDecisionLocked(actor.TenantID, scan, finding, in, "api", actor.KeyID, "", in.VEXDocumentID)
	l.decisions[decision.ID] = decision
	l.appendDecisionLifecycleAuditLocked(actor.TenantID, decision, finding.ID, "api_key", actor.KeyID, "")
	if err := l.persistCriticalLocked(ctx, l.criticalMutationLocked()); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	return decision, nil
}

func (s releaseEvidenceService) ListVulnerabilityDecisions(ctx context.Context, actor domain.Actor, in ListVulnerabilityDecisionsInput) ([]domain.VulnerabilityDecision, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	in.ProductID = strings.TrimSpace(in.ProductID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.Vulnerability = strings.TrimSpace(in.Vulnerability)
	in.Component = strings.TrimSpace(in.Component)
	in.Status = strings.TrimSpace(in.Status)
	if in.Status != "" && !validDecisionStatus(in.Status) {
		return nil, ErrValidation
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	filterProductID := in.ProductID
	if filterProductID != "" {
		product, ok := l.products[filterProductID]
		if !ok || product.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: product.ID}); err != nil {
			return nil, err
		}
	}
	if in.ReleaseID != "" {
		release, ok := l.releases[in.ReleaseID]
		if !ok || release.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
		if filterProductID != "" && release.ProductID != filterProductID {
			return nil, ErrNotFound
		}
		filterProductID = release.ProductID
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
			return nil, err
		}
	}

	out := []domain.VulnerabilityDecision{}
	for _, decision := range l.decisions {
		if decision.TenantID != actor.TenantID {
			continue
		}
		if in.ReleaseID != "" && decision.ReleaseID != in.ReleaseID {
			continue
		}
		releaseProductID := ""
		if decision.ReleaseID != "" {
			release, ok := l.releases[decision.ReleaseID]
			if !ok || release.TenantID != actor.TenantID {
				continue
			}
			releaseProductID = release.ProductID
		}
		if filterProductID != "" && releaseProductID != filterProductID {
			continue
		}
		if in.Vulnerability != "" && decision.Vulnerability != in.Vulnerability {
			continue
		}
		if in.Component != "" && decision.Component != in.Component {
			continue
		}
		if in.Status != "" && decision.Status != in.Status {
			continue
		}
		if in.Active != nil && (*in.Active) != (decision.SupersededBy == "") {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: releaseProductID, ReleaseID: decision.ReleaseID}) {
			continue
		}
		out = append(out, decision)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s releaseEvidenceService) VulnerabilityDecisionSummaryReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityDecisionSummaryReport, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityDecisionSummaryReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.VulnerabilityDecisionSummaryReport{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return domain.VulnerabilityDecisionSummaryReport{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[releaseID]
	if !ok || release.TenantID != actor.TenantID {
		return domain.VulnerabilityDecisionSummaryReport{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.VulnerabilityDecisionSummaryReport{}, err
	}
	decisions := []domain.VulnerabilityDecisionCustomerSummary{}
	for _, decision := range l.decisions {
		if decision.TenantID != actor.TenantID || decision.ReleaseID != release.ID || decision.SupersededBy != "" || !decision.CustomerVisible {
			continue
		}
		decisions = append(decisions, customerDecisionSummary(decision))
	}
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].CreatedAt.Equal(decisions[j].CreatedAt) {
			return decisions[i].ID < decisions[j].ID
		}
		return decisions[i].CreatedAt.Before(decisions[j].CreatedAt)
	})
	return domain.VulnerabilityDecisionSummaryReport{
		ReportType:      "vulnerability_decision_summary",
		TemplateVersion: "vulnerability-decision-summary.v1.0.0",
		ProductID:       release.ProductID,
		ReleaseID:       release.ID,
		Decisions:       decisions,
		Assumptions: []string{
			"Only active vulnerability decisions marked customer_visible are included.",
			"Evidence identifiers point to records in this Evydence instance; raw evidence payload bytes are not included.",
			"reviewed_at records when the decision was reviewed; missing review_due_at means no scheduled follow-up review was recorded.",
		},
		Limitations: []string{
			"This summary supports compliance-readiness review; it is not certification, legal advice, complete SBOM proof, or authoritative vulnerability coverage.",
			"Decision accuracy depends on tenant-supplied evidence, scanner inputs, and review quality.",
			"Review dates are tenant-supplied metadata and do not prove that the underlying vulnerability analysis is still correct.",
		},
		GeneratedAt: l.now(),
	}, nil
}

func customerDecisionSummary(decision domain.VulnerabilityDecision) domain.VulnerabilityDecisionCustomerSummary {
	return domain.VulnerabilityDecisionCustomerSummary{
		ID:              decision.ID,
		FindingID:       decision.FindingID,
		ScanID:          decision.ScanID,
		ReleaseID:       decision.ReleaseID,
		Vulnerability:   decision.Vulnerability,
		Component:       decision.Component,
		Status:          decision.Status,
		Justification:   decision.Justification,
		ImpactStatement: decision.ImpactStatement,
		ActionStatement: decision.ActionStatement,
		Source:          decision.Source,
		EvidenceID:      decision.EvidenceID,
		EvidenceIDs:     append([]string(nil), decision.EvidenceIDs...),
		VEXDocumentID:   decision.VEXDocumentID,
		ReviewedAt:      cloneTimePtr(decision.ReviewedAt),
		ReviewDueAt:     cloneTimePtr(decision.ReviewDueAt),
		CreatedAt:       decision.CreatedAt,
	}
}

func (s releaseEvidenceService) CreateException(ctx context.Context, actor domain.Actor, in CreateExceptionInput) (domain.Exception, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Exception{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.Exception{}, err
	}
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.FindingID = strings.TrimSpace(in.FindingID)
	in.Reason = strings.TrimSpace(in.Reason)
	in.Owner = strings.TrimSpace(in.Owner)
	if in.ReleaseID == "" || in.Reason == "" || in.Owner == "" || !in.ExpiresAt.After(l.now()) {
		return domain.Exception{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[in.ReleaseID]
	if !ok || release.TenantID != actor.TenantID {
		return domain.Exception{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.Exception{}, err
	}
	if in.FindingID != "" {
		scan, _, ok := l.findFindingLocked(actor.TenantID, in.FindingID)
		if !ok || scan.ReleaseID != in.ReleaseID {
			return domain.Exception{}, ErrNotFound
		}
	}
	if strings.TrimSpace(in.ControlID) != "" {
		control, ok := l.controls[strings.TrimSpace(in.ControlID)]
		if !ok || control.TenantID != actor.TenantID {
			return domain.Exception{}, ErrNotFound
		}
	}
	exception := domain.Exception{
		ID:        newID("ex"),
		TenantID:  actor.TenantID,
		ReleaseID: in.ReleaseID,
		FindingID: in.FindingID,
		ControlID: strings.TrimSpace(in.ControlID),
		Reason:    in.Reason,
		Owner:     in.Owner,
		ExpiresAt: in.ExpiresAt.UTC(),
		Approved:  false,
		CreatedAt: l.now(),
	}
	l.exceptions[exception.ID] = exception
	_, _ = l.appendChainLocked(actor.TenantID, "exception.created", "exception", exception.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Exception{}, err
	}
	return exception, nil
}

func (s releaseEvidenceService) ListExceptions(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.Exception, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.Exception{}
	for _, exception := range l.exceptions {
		if exception.TenantID != actor.TenantID {
			continue
		}
		if releaseID != "" && exception.ReleaseID != releaseID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeVerifyRead, resourceRefs{ReleaseID: exception.ReleaseID}) {
			continue
		}
		out = append(out, exception)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s releaseEvidenceService) ApproveException(ctx context.Context, actor domain.Actor, id string) (domain.Exception, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Exception{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.Exception{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	exception, ok := l.exceptions[strings.TrimSpace(id)]
	if !ok || exception.TenantID != actor.TenantID {
		return domain.Exception{}, ErrNotFound
	}
	if !exception.ExpiresAt.After(l.now()) {
		return domain.Exception{}, ErrConflict
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ReleaseID: exception.ReleaseID}); err != nil {
		return domain.Exception{}, err
	}
	if exception.Approved {
		return exception, nil
	}
	now := l.now()
	exception.Approved = true
	exception.ApprovedBy = actor.KeyID
	exception.ApprovedAt = &now
	l.exceptions[exception.ID] = exception
	_, _ = l.appendChainLocked(actor.TenantID, "exception.approved", "exception", exception.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Exception{}, err
	}
	return exception, nil
}

func (s releaseEvidenceService) ReleaseReadinessReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseReadinessReport, error) {
	l := s.ledger
	eval, err := l.EvaluateRelease(ctx, actor, releaseID)
	if err != nil {
		return domain.ReleaseReadinessReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	blocking := l.unhandledCriticalFindingsLocked(actor.TenantID, eval.ReleaseID)
	accepted := l.acceptedExceptionsForReleaseLocked(actor.TenantID, eval.ReleaseID)
	gaps := []string{}
	for _, check := range eval.Checks {
		gaps = append(gaps, check.Missing...)
	}
	gaps = sortedUniqueNonEmptyStrings(gaps)
	failedPolicies := failedPolicyNames(eval.Checks)
	knownLimitations := releaseReadinessKnownLimitations()
	nonClaims := releaseReadinessNonClaims()
	sections := l.releaseReadinessSectionsLocked(actor.TenantID, eval.ReleaseID, eval, blocking, accepted, gaps, failedPolicies, knownLimitations)
	return domain.ReleaseReadinessReport{
		ReportType:         "release_readiness",
		TemplateVersion:    domain.ReleaseReadinessTemplateVersion,
		ReleaseID:          eval.ReleaseID,
		Result:             eval.Result,
		PolicySet:          eval.PolicySet,
		Summary:            releaseReadinessSummary(eval, len(blocking), len(gaps), len(failedPolicies)),
		Checks:             eval.Checks,
		Sections:           sections,
		BlockingFindings:   blocking,
		AcceptedExceptions: accepted,
		Gaps:               gaps,
		MissingEvidence:    gaps,
		FailedPolicies:     failedPolicies,
		KnownLimitations:   knownLimitations,
		NonClaims:          nonClaims,
		Assumptions:        []string{"This report supports compliance readiness and technical evidence review; it is not a legal compliance conclusion."},
		Limitations:        knownLimitations,
		GeneratedAt:        l.now(),
	}, nil
}

func releaseReadinessSummary(eval domain.PolicyEvaluation, blockingCount, missingCount, failedCount int) domain.ReadinessSummary {
	if eval.Result == "passed" {
		return domain.ReadinessSummary{
			Headline:     "Recorded release evidence satisfies the current built-in readiness checks.",
			Result:       eval.Result,
			HumanSummary: "The report found no blocking policy failures in the recorded release evidence. Review the limitations and non-claims before sharing externally.",
			PolicySet:    eval.PolicySet,
		}
	}
	return domain.ReadinessSummary{
		Headline:     "Recorded release evidence has readiness blockers or missing inputs.",
		Result:       eval.Result,
		HumanSummary: fmt.Sprintf("The report found %d failed policy checks, %d missing evidence inputs, and %d blocking findings in the recorded release evidence.", failedCount, missingCount, blockingCount),
		PolicySet:    eval.PolicySet,
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

func failedPolicyNames(checks []domain.PolicyCheck) []string {
	out := []string{}
	for _, check := range checks {
		if check.Result == "failed" {
			out = append(out, check.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (l *Ledger) releaseReadinessSectionsLocked(tenantID, releaseID string, eval domain.PolicyEvaluation, blocking []domain.BlockingFinding, accepted []domain.Exception, missingEvidence, failedPolicies, knownLimitations []string) []domain.ReadinessSection {
	checks := readinessChecksByName(eval.Checks)
	decisionCount := l.activeDecisionCountForReleaseLocked(tenantID, releaseID)
	hasPackage := l.hasActiveCustomerPackageLocked(tenantID, releaseID)
	sections := []domain.ReadinessSection{
		readinessSection("release_evidence", "Release Evidence", []domain.ReadinessQuestion{
			readinessQuestionForCheck(checks["release_has_artifact"], "release_has_artifact", "Is a release artifact linked?", "Artifact evidence is linked to the release.", "Release artifact evidence is missing."),
			readinessQuestionForCheck(checks["release_requires_artifact_digest"], "artifact_digest", "Are artifact digests present?", "Artifact digest evidence is linked to the release.", "Release artifact digest evidence is missing."),
			readinessQuestionForCheck(checks["release_requires_sbom"], "sbom", "Is there an SBOM for this release?", "SBOM evidence is recorded for this release.", "SBOM evidence is missing for this release."),
			readinessQuestionForCheck(checks["release_requires_vulnerability_scan"], "vulnerability_scan", "Is there a vulnerability scan?", "Vulnerability scan evidence is recorded for this release.", "Vulnerability scan evidence is missing for this release."),
		}),
		readinessSection("risk_decisions", "Vulnerability Decisions", []domain.ReadinessQuestion{
			readinessQuestionForCheck(checks["critical_exploitable_blocks_release"], "critical_findings_triaged", "Are open critical findings triaged?", "No unhandled open critical findings are recorded.", "One or more open critical findings require a valid decision, remediation, or approved unexpired exception."),
			readinessQuestionForCheck(checks["high_findings_require_triage"], "high_findings_triaged", "Are open high findings triaged?", "No unhandled open high findings are recorded.", "One or more open high findings require a valid decision, remediation, or approved unexpired exception."),
			readinessDecisionQuestion(decisionCount, len(blocking)),
			readinessQuestionForCheck(checks["customer_visible_decisions_require_statements"], "customer_visible_decision_statements", "Do customer-visible decisions have review-safe statements?", "Customer-visible decisions have required impact statements.", "One or more customer-visible decisions is missing an impact statement."),
			readinessQuestionForCheck(checks["not_affected_decisions_require_justification"], "not_affected_justifications", "Do not_affected decisions include justifications?", "not_affected decisions include recorded justifications.", "One or more not_affected decisions is missing a justification."),
			readinessExceptionQuestion(accepted),
			readinessQuestionForCheck(checks["exceptions_require_owner_reason_expiry_and_approval"], "exception_completeness", "Are exceptions complete?", "Release exceptions have required owner, reason, expiry, and approval metadata.", "One or more exceptions is incomplete."),
		}),
		readinessSection("provenance", "Build Provenance And Bundle", []domain.ReadinessQuestion{
			readinessQuestionForCheck(checks["release_requires_passed_build"], "passed_build", "Is passed build provenance attached?", "A passed build is linked to a release artifact digest.", "No passed build with output digest linked to the release was found."),
			readinessQuestionForCheck(checks["release_requires_build_attestation"], "build_attestation", "Is there a build attestation for a release artifact?", "A build attestation subject matches a release artifact digest.", "No build attestation subject matches a release artifact digest."),
			readinessQuestionForCheck(checks["release_requires_signed_bundle"], "signed_bundle", "Is there a signed release bundle?", "A signed release bundle exists for this release.", "A signed release bundle is missing for this release."),
		}),
		readinessSection("customer_review", "Customer Package Review", []domain.ReadinessQuestion{
			readinessCustomerPackageQuestion(hasPackage),
			readinessQuestionForCheck(checks["package_redaction_profile_valid"], "package_redaction_profile_valid", "Is the customer package redaction profile valid?", "Recorded package redaction profiles are explicit and exclude sensitive fields, or no package exists yet.", "One or more packages has an expired or incomplete redaction profile."),
		}),
		readinessSection("gaps_and_limitations", "Gaps And Limitations", []domain.ReadinessQuestion{
			readinessGapQuestion(missingEvidence, failedPolicies),
			{ID: "known_limitations", Question: "What limitations apply?", Answer: "Read the known_limitations and non_claims fields before using this report.", Status: "limited", KnownLimitations: append([]string(nil), knownLimitations...)},
		}),
	}
	return sections
}

func readinessChecksByName(checks []domain.PolicyCheck) map[string]domain.PolicyCheck {
	out := map[string]domain.PolicyCheck{}
	for _, check := range checks {
		out[check.Name] = check
	}
	return out
}

func readinessSection(id, title string, questions []domain.ReadinessQuestion) domain.ReadinessSection {
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
	return domain.ReadinessSection{ID: id, Title: title, Status: status, Summary: readinessSectionSummary(status), Questions: questions}
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

func readinessQuestionForCheck(check domain.PolicyCheck, id, question, passedAnswer, failedAnswer string) domain.ReadinessQuestion {
	if check.Name == "" {
		return domain.ReadinessQuestion{ID: id, Question: question, Answer: "No policy check was recorded for this question.", Status: "limited", KnownLimitations: []string{"Policy coverage for this question is not configured."}}
	}
	if check.Result == "passed" {
		return domain.ReadinessQuestion{ID: id, Question: question, Answer: passedAnswer, Status: "passed", Checks: []string{check.Name}}
	}
	status := "failed_policy"
	if len(check.Missing) > 0 {
		status = "missing_evidence"
	}
	return domain.ReadinessQuestion{ID: id, Question: question, Answer: failedAnswer, Status: status, Checks: []string{check.Name}, MissingEvidence: append([]string(nil), check.Missing...), FailedPolicies: []string{check.Name}}
}

func readinessDecisionQuestion(decisionCount, blockingCount int) domain.ReadinessQuestion {
	if blockingCount > 0 {
		return domain.ReadinessQuestion{ID: "vex_decisions_for_blockers", Question: "Are VEX or vulnerability decisions present for blocking findings?", Answer: fmt.Sprintf("%d blocking finding(s) still need a valid decision, remediation, or approved exception.", blockingCount), Status: "failed_policy", MissingEvidence: []string{"vulnerability_decision"}, FailedPolicies: []string{"critical_exploitable_blocks_release"}}
	}
	if decisionCount > 0 {
		return domain.ReadinessQuestion{ID: "vex_decisions_for_blockers", Question: "Are VEX or vulnerability decisions present for blocking findings?", Answer: fmt.Sprintf("%d active vulnerability decision(s) are recorded for this release.", decisionCount), Status: "passed", Evidence: []string{"vulnerability_decision"}}
	}
	return domain.ReadinessQuestion{ID: "vex_decisions_for_blockers", Question: "Are VEX or vulnerability decisions present for blocking findings?", Answer: "No active vulnerability decisions are recorded; no blocking findings currently require one.", Status: "limited", KnownLimitations: []string{"Decision evidence is only expected when findings require triage or customer-visible explanation."}}
}

func readinessExceptionQuestion(accepted []domain.Exception) domain.ReadinessQuestion {
	if len(accepted) > 0 {
		return domain.ReadinessQuestion{ID: "approved_exceptions", Question: "Are exceptions approved and unexpired?", Answer: fmt.Sprintf("%d approved unexpired exception(s) are accepted for this release.", len(accepted)), Status: "passed", Evidence: []string{"exception"}}
	}
	return domain.ReadinessQuestion{ID: "approved_exceptions", Question: "Are exceptions approved and unexpired?", Answer: "No approved unexpired release exceptions are used by this report.", Status: "limited", KnownLimitations: []string{"No exception is needed when policy checks pass without an accepted exception."}}
}

func readinessCustomerPackageQuestion(hasPackage bool) domain.ReadinessQuestion {
	if hasPackage {
		return domain.ReadinessQuestion{ID: "customer_package_safe_to_share", Question: "Is a customer package available for review?", Answer: "A non-expired customer package is recorded for this release; review its redaction profile before sharing.", Status: "passed", Evidence: []string{"customer_package"}}
	}
	return domain.ReadinessQuestion{ID: "customer_package_safe_to_share", Question: "Is a customer package available for review?", Answer: "No customer package was evaluated by this release readiness report.", Status: "limited", KnownLimitations: []string{"Package shareability is evaluated when a scoped customer package is generated."}}
}

func readinessGapQuestion(missingEvidence, failedPolicies []string) domain.ReadinessQuestion {
	if len(missingEvidence) == 0 && len(failedPolicies) == 0 {
		return domain.ReadinessQuestion{ID: "remaining_gaps", Question: "What gaps remain?", Answer: "No blocking readiness gaps are recorded by the current policy checks.", Status: "passed"}
	}
	status := "failed_policy"
	if len(failedPolicies) == 0 {
		status = "missing_evidence"
	}
	return domain.ReadinessQuestion{ID: "remaining_gaps", Question: "What gaps remain?", Answer: "The report lists missing evidence and failed policy checks that should be reviewed.", Status: status, MissingEvidence: append([]string(nil), missingEvidence...), FailedPolicies: append([]string(nil), failedPolicies...)}
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

func (l *Ledger) checkCustomerVisibleDecisionsHaveStatementsLocked(tenantID, releaseID string) domain.PolicyCheck {
	missing := []string{}
	for _, decision := range l.decisions {
		if decision.TenantID != tenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" || !decision.CustomerVisible {
			continue
		}
		if strings.TrimSpace(decision.ImpactStatement) == "" {
			missing = append(missing, decision.ID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return domain.PolicyCheck{Name: "customer_visible_decisions_require_statements", Result: "failed", Severity: "high", Missing: missing, Explanation: "customer-visible decisions require an impact statement suitable for package summaries", Remediation: "Create a superseding customer-visible decision with a clear impact statement and no internal-only notes in customer-facing fields."}
	}
	return domain.PolicyCheck{Name: "customer_visible_decisions_require_statements", Result: "passed", Severity: "high", Explanation: "customer-visible decisions have required impact statements"}
}

func (l *Ledger) checkNotAffectedDecisionsHaveJustificationLocked(tenantID, releaseID string) domain.PolicyCheck {
	missing := []string{}
	for _, decision := range l.decisions {
		if decision.TenantID != tenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" || decision.Status != decisionStatusNotAffected {
			continue
		}
		if strings.TrimSpace(decision.Justification) == "" {
			missing = append(missing, decision.ID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return domain.PolicyCheck{Name: "not_affected_decisions_require_justification", Result: "failed", Severity: "high", Missing: missing, Explanation: "not_affected decisions require a recorded justification", Remediation: "Create a superseding not_affected decision with a specific technical justification."}
	}
	return domain.PolicyCheck{Name: "not_affected_decisions_require_justification", Result: "passed", Severity: "high", Explanation: "not_affected decisions have recorded justifications"}
}

func (l *Ledger) checkExceptionsCompleteLocked(tenantID, releaseID string) domain.PolicyCheck {
	missing := []string{}
	for _, exception := range l.exceptions {
		if exception.TenantID != tenantID || exception.ReleaseID != releaseID {
			continue
		}
		if strings.TrimSpace(exception.Owner) == "" || strings.TrimSpace(exception.Reason) == "" || exception.ExpiresAt.IsZero() || (exception.Approved && (strings.TrimSpace(exception.ApprovedBy) == "" || exception.ApprovedAt == nil)) {
			missing = append(missing, exception.ID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return domain.PolicyCheck{Name: "exceptions_require_owner_reason_expiry_and_approval", Result: "failed", Severity: "high", Missing: missing, Explanation: "exceptions must include owner, reason, expiry, and approval metadata when approved", Remediation: "Create a complete exception with owner, reason, future expiry, and an audited approval transition."}
	}
	return domain.PolicyCheck{Name: "exceptions_require_owner_reason_expiry_and_approval", Result: "passed", Severity: "high", Explanation: "release exceptions have required completeness fields"}
}

func (l *Ledger) checkPackageRedactionProfilesValidLocked(tenantID, releaseID string) domain.PolicyCheck {
	missing := []string{}
	sawPackage := false
	for _, pkg := range l.customerPackages {
		if pkg.TenantID != tenantID || pkg.ReleaseID != releaseID {
			continue
		}
		sawPackage = true
		profile, ok := l.redactions[pkg.RedactionProfileID]
		if !ok || profile.TenantID != tenantID || len(profile.AllowedTypes) == 0 || !redactionProfileExcludesPackageSensitiveFields(profile) || !pkg.ExpiresAt.After(l.now()) {
			missing = append(missing, pkg.ID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return domain.PolicyCheck{Name: "package_redaction_profile_valid", Result: "failed", Severity: "high", Missing: missing, Explanation: "one or more customer packages has an expired package or redaction profile that does not explicitly exclude sensitive fields", Remediation: "Create a new package with the customer_safe or security_review preset, or configure explicit allowed types and sensitive-field exclusions."}
	}
	if !sawPackage {
		return domain.PolicyCheck{Name: "package_redaction_profile_valid", Result: "passed", Severity: "medium", Explanation: "no customer package is recorded for this release; redaction profile validation applies when a package exists"}
	}
	return domain.PolicyCheck{Name: "package_redaction_profile_valid", Result: "passed", Severity: "high", Explanation: "customer package redaction profiles are explicit and exclude sensitive fields"}
}

func redactionProfileExcludesPackageSensitiveFields(profile domain.RedactionProfile) bool {
	required := map[string]struct{}{"payload_ref": {}, "object_key": {}, "private_key": {}, "token": {}, "secret": {}, "internal_notes": {}}
	for _, field := range profile.ExcludedFields {
		delete(required, strings.ToLower(strings.TrimSpace(field)))
	}
	return len(required) == 0
}

func parseOpenVEX(raw []byte) (openVEXDocument, error) {
	var doc openVEXDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return openVEXDocument{}, vexValidationError("openvex JSON is malformed or contains unsupported fields")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return openVEXDocument{}, vexValidationError("openvex JSON must contain a single document")
	}
	doc.Author = strings.TrimSpace(doc.Author)
	doc.Timestamp = strings.TrimSpace(doc.Timestamp)
	if doc.Author == "" {
		return openVEXDocument{}, vexValidationError("openvex author is required")
	}
	if doc.Timestamp == "" {
		return openVEXDocument{}, vexValidationError("openvex timestamp is required")
	}
	if len(doc.Statements) == 0 {
		return openVEXDocument{}, vexValidationError("openvex must include at least one statement")
	}
	if _, err := time.Parse(time.RFC3339, doc.Timestamp); err != nil {
		return openVEXDocument{}, vexValidationError("openvex timestamp must be RFC3339")
	}
	for index := range doc.Statements {
		statement := &doc.Statements[index]
		statement.Vulnerability.Name = strings.TrimSpace(statement.Vulnerability.Name)
		statement.Status = strings.TrimSpace(statement.Status)
		statement.Justification = strings.TrimSpace(statement.Justification)
		statement.ImpactStatement = strings.TrimSpace(statement.ImpactStatement)
		statement.ActionStatement = strings.TrimSpace(statement.ActionStatement)
		if statement.Vulnerability.Name == "" {
			return openVEXDocument{}, vexStatementValidationError(index+1, "is missing a vulnerability name")
		}
		if !validDecisionStatus(statement.Status) {
			return openVEXDocument{}, vexStatementValidationError(index+1, "has an unsupported status")
		}
		if statement.Justification == "" {
			return openVEXDocument{}, vexStatementValidationError(index+1, "is missing a justification")
		}
		if len(statement.Products) == 0 {
			return openVEXDocument{}, vexStatementValidationError(index+1, "is missing products")
		}
		if err := validateOpenVEXProducts(index+1, statement.Products); err != nil {
			return openVEXDocument{}, err
		}
	}
	return doc, nil
}

func validateOpenVEXProducts(statementIndex int, products []openVEXProduct) error {
	for index := range products {
		products[index].ID = strings.TrimSpace(products[index].ID)
		if products[index].ID == "" {
			return vexValidationError(fmt.Sprintf("openvex statement %d product %d is missing an @id", statementIndex, index+1))
		}
		if err := validateOpenVEXProducts(statementIndex, products[index].Subcomponents); err != nil {
			return err
		}
	}
	return nil
}

func vexStatementValidationError(index int, detail string) error {
	return vexValidationError(fmt.Sprintf("openvex statement %d %s", index, detail))
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

func validDecisionTransition(from, to string) bool {
	to = strings.TrimSpace(to)
	if strings.TrimSpace(from) == "" {
		return validDecisionStatus(to)
	}
	allowed, ok := decisionStatusTransitions[strings.TrimSpace(from)]
	if !ok {
		return false
	}
	_, ok = allowed[to]
	return ok
}

func decisionStatusSet(statuses ...string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, status := range statuses {
		set[status] = struct{}{}
	}
	return set
}

func versionString(version any) string {
	switch v := version.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return ""
	}
}

type matchedFinding struct {
	scan    domain.VulnerabilityScan
	finding domain.VulnerabilityFinding
}

func (l *Ledger) findMatchingFindingsLocked(tenantID, releaseID string, statement openVEXStatement) []matchedFinding {
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
	return out
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

func (l *Ledger) createDecisionLocked(tenantID string, scan domain.VulnerabilityScan, finding domain.VulnerabilityFinding, in CreateVulnerabilityDecisionInput, source, actorID, evidenceID, vexID string) domain.VulnerabilityDecision {
	decisionID := newID("vd")
	createdAt := l.now()
	var supersedes string
	for id, existing := range l.decisions {
		if existing.TenantID == tenantID && existing.FindingID == finding.ID && existing.SupersededBy == "" {
			supersedes = existing.ID
			existing.SupersededBy = decisionID
			l.decisions[id] = existing
		}
	}
	decision := domain.VulnerabilityDecision{
		ID:              decisionID,
		TenantID:        tenantID,
		FindingID:       finding.ID,
		ScanID:          scan.ID,
		ReleaseID:       scan.ReleaseID,
		Vulnerability:   finding.Vulnerability,
		Component:       finding.Component,
		Status:          strings.TrimSpace(in.Status),
		Justification:   strings.TrimSpace(in.Justification),
		ImpactStatement: strings.TrimSpace(in.ImpactStatement),
		ActionStatement: strings.TrimSpace(in.ActionStatement),
		CustomerVisible: in.CustomerVisible,
		InternalNotes:   strings.TrimSpace(in.InternalNotes),
		Source:          source,
		EvidenceID:      evidenceID,
		EvidenceIDs:     decisionEvidenceIDs(evidenceID, in.EvidenceIDs),
		VEXDocumentID:   vexID,
		Supersedes:      supersedes,
		ApprovedBy:      actorID,
		ReviewedAt:      decisionReviewedAt(in.ReviewedAt, createdAt),
		ReviewDueAt:     cloneTimePtr(in.ReviewDueAt),
		SchemaVersion:   domain.VulnerabilityDecisionVersion,
		CreatedAt:       createdAt,
	}
	return decision
}

func normalizeDecisionReviewTimes(in *CreateVulnerabilityDecisionInput, now time.Time) error {
	now = now.UTC()
	var reviewedAt time.Time
	if in.ReviewedAt != nil {
		if in.ReviewedAt.IsZero() || in.ReviewedAt.After(now.Add(time.Minute)) {
			return ErrValidation
		}
		reviewedAt = in.ReviewedAt.UTC()
		in.ReviewedAt = &reviewedAt
	} else {
		reviewedAt = now
	}
	if in.ReviewDueAt != nil {
		if in.ReviewDueAt.IsZero() {
			return ErrValidation
		}
		dueAt := in.ReviewDueAt.UTC()
		if !dueAt.After(reviewedAt) {
			return ErrValidation
		}
		in.ReviewDueAt = &dueAt
	}
	return nil
}

func decisionReviewedAt(reviewedAt *time.Time, fallback time.Time) *time.Time {
	if reviewedAt != nil {
		return cloneTimePtr(reviewedAt)
	}
	value := fallback.UTC()
	return &value
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := value.UTC()
	return &clone
}

func (l *Ledger) validateDecisionEvidenceLinksLocked(tenantID, releaseID string, evidenceIDs []string) ([]string, error) {
	ids := sortedUniqueNonEmptyStrings(evidenceIDs)
	if len(evidenceIDs) != len(ids) {
		// Empty values are malformed; duplicate non-empty values are normalized below.
		nonEmpty := 0
		for _, id := range evidenceIDs {
			if strings.TrimSpace(id) != "" {
				nonEmpty++
			}
		}
		if nonEmpty != len(evidenceIDs) {
			return nil, ErrValidation
		}
	}
	for _, id := range ids {
		item, ok := l.evidence[id]
		if !ok || item.TenantID != tenantID {
			return nil, ErrNotFound
		}
		if item.ReleaseID != "" && releaseID != "" && item.ReleaseID != releaseID {
			return nil, ErrNotFound
		}
	}
	return ids, nil
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

func (l *Ledger) appendDecisionLifecycleAuditLocked(tenantID string, decision domain.VulnerabilityDecision, findingID, actorTypeValue, actorIDValue, payloadHash string) {
	if decision.Supersedes != "" {
		_, _ = l.appendChainLocked(tenantID, "vulnerability_decision.superseded", "vulnerability_decision", decision.Supersedes, actorTypeValue, actorIDValue, payloadHash, "")
	}
	_, _ = l.appendChainLocked(tenantID, "vulnerability_decision.created", "vulnerability_finding", findingID, actorTypeValue, actorIDValue, payloadHash, "")
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

func (l *Ledger) checkReleaseHasArtifactDigestLocked(tenantID, releaseID string) domain.PolicyCheck {
	for _, item := range l.evidence {
		if item.TenantID != tenantID || item.ReleaseID != releaseID {
			continue
		}
		for _, ref := range item.SubjectRefs {
			if ref.Type == "artifact" && ref.ID != "" {
				return domain.PolicyCheck{Name: "release_requires_artifact_digest", Result: "passed", Severity: "high", Explanation: "artifact digest evidence is linked to the release"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_artifact_digest", Result: "failed", Severity: "high", Missing: []string{"artifact_digest"}, Explanation: "release artifact digest evidence is missing", Remediation: "Register an artifact digest and link it to release evidence."}
}

func (l *Ledger) checkReleaseHasSignedBundleLocked(tenantID, releaseID string) domain.PolicyCheck {
	for _, bundle := range l.bundles {
		if bundle.TenantID != tenantID || bundle.ReleaseID != releaseID {
			continue
		}
		if len(bundle.SignatureRefs) > 0 && l.verifySignatureLocked(tenantID, bundle.SignatureRefs, []byte(bundle.ManifestHash)) {
			return domain.PolicyCheck{Name: "release_requires_signed_bundle", Result: "passed", Severity: "high", Explanation: "signed release bundle exists"}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_signed_bundle", Result: "failed", Severity: "high", Missing: []string{"signed_release_bundle"}, Explanation: "signed release bundle is missing", Remediation: "Generate a release bundle after required evidence is recorded."}
}
