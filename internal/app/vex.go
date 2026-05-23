package app

import (
	"bytes"
	"context"
	"encoding/json"
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

type CreateVulnerabilityDecisionInput struct {
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
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

func (l *Ledger) UploadVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
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
	l.vexDocuments[vex.ID] = vex
	createdDecisions := 0
	for _, statement := range doc.Statements {
		for _, matched := range l.findMatchingFindingsLocked(actor.TenantID, releaseID, statement) {
			decision := l.createDecisionLocked(actor.TenantID, matched.scan, matched.finding, CreateVulnerabilityDecisionInput{
				Status:          statement.Status,
				Justification:   statement.Justification,
				ImpactStatement: statement.ImpactStatement,
				ActionStatement: statement.ActionStatement,
			}, "vex", actor.KeyID, item.ID, vex.ID)
			l.decisions[decision.ID] = decision
			createdDecisions++
		}
	}
	_, _ = l.appendChainLocked(actor.TenantID, "vex.parsed", "vex_document", vex.ID, "api_key", actor.KeyID, payloadHash, "")
	if err := l.enqueue(ctx, actor.TenantID, "parse_vex", "vex_document", vex.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "decisions_created": createdDecisions}); err != nil {
		return domain.VEXDocument{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.VEXDocument{}, err
	}
	return vex, nil
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
	vex, ok := l.vexDocuments[strings.TrimSpace(id)]
	if !ok || vex.TenantID != actor.TenantID {
		return domain.VEXDocument{}, ErrNotFound
	}
	return vex, nil
}

func (l *Ledger) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, findingID string, in CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	if !validDecisionStatus(in.Status) || strings.TrimSpace(in.Justification) == "" {
		return domain.VulnerabilityDecision{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	scan, finding, ok := l.findFindingLocked(actor.TenantID, strings.TrimSpace(findingID))
	if !ok {
		return domain.VulnerabilityDecision{}, ErrNotFound
	}
	decision := l.createDecisionLocked(actor.TenantID, scan, finding, in, "api", actor.KeyID, "", "")
	l.decisions[decision.ID] = decision
	_, _ = l.appendChainLocked(actor.TenantID, "vulnerability_decision.created", "vulnerability_finding", finding.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.VulnerabilityDecision{}, err
	}
	return decision, nil
}

func (l *Ledger) CreateException(ctx context.Context, actor domain.Actor, in CreateExceptionInput) (domain.Exception, error) {
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
	if in.FindingID != "" {
		scan, _, ok := l.findFindingLocked(actor.TenantID, in.FindingID)
		if !ok || scan.ReleaseID != in.ReleaseID {
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

func (l *Ledger) ListExceptions(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.Exception, error) {
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
		out = append(out, exception)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (l *Ledger) ApproveException(ctx context.Context, actor domain.Actor, id string) (domain.Exception, error) {
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

func (l *Ledger) ReleaseReadinessReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseReadinessReport, error) {
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
	sort.Strings(gaps)
	return domain.ReleaseReadinessReport{
		ReportType:         "release_readiness",
		TemplateVersion:    domain.ReleaseReadinessTemplateVersion,
		ReleaseID:          eval.ReleaseID,
		Result:             eval.Result,
		Checks:             eval.Checks,
		BlockingFindings:   blocking,
		AcceptedExceptions: accepted,
		Gaps:               gaps,
		Assumptions:        []string{"This report supports compliance readiness and is not a legal compliance conclusion."},
		Limitations:        []string{"Readiness is based only on evidence, decisions, exceptions, and bundles recorded in this Evydence instance."},
		GeneratedAt:        l.now(),
	}, nil
}

func parseOpenVEX(raw []byte) (openVEXDocument, error) {
	var doc openVEXDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return openVEXDocument{}, ErrValidation
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return openVEXDocument{}, ErrValidation
	}
	if strings.TrimSpace(doc.Author) == "" || strings.TrimSpace(doc.Timestamp) == "" || len(doc.Statements) == 0 {
		return openVEXDocument{}, ErrValidation
	}
	if _, err := time.Parse(time.RFC3339, doc.Timestamp); err != nil {
		return openVEXDocument{}, ErrValidation
	}
	for _, statement := range doc.Statements {
		if strings.TrimSpace(statement.Vulnerability.Name) == "" || !validDecisionStatus(statement.Status) || strings.TrimSpace(statement.Justification) == "" {
			return openVEXDocument{}, ErrValidation
		}
		if len(statement.Products) == 0 {
			return openVEXDocument{}, ErrValidation
		}
		for _, product := range statement.Products {
			if strings.TrimSpace(product.ID) == "" {
				return openVEXDocument{}, ErrValidation
			}
		}
	}
	return doc, nil
}

func validDecisionStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation:
		return true
	default:
		return false
	}
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
		Source:          source,
		EvidenceID:      evidenceID,
		VEXDocumentID:   vexID,
		Supersedes:      supersedes,
		ApprovedBy:      actorID,
		SchemaVersion:   domain.VulnerabilityDecisionVersion,
		CreatedAt:       l.now(),
	}
	return decision
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
	blocking := []domain.BlockingFinding{}
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		for _, finding := range scan.Findings {
			if strings.ToLower(finding.Severity) != "critical" || strings.ToLower(nonEmpty(finding.State, "open")) != "open" {
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
	return domain.PolicyCheck{Name: "release_requires_artifact_digest", Result: "failed", Severity: "high", Missing: []string{"artifact_digest"}, Explanation: "release artifact digest evidence is missing"}
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
	return domain.PolicyCheck{Name: "release_requires_signed_bundle", Result: "failed", Severity: "high", Missing: []string{"signed_release_bundle"}, Explanation: "signed release bundle is missing"}
}
