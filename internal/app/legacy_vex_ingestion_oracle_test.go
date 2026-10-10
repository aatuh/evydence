package app

import (
	"context"
	"strings"

	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical VEX uploads and preview helpers: test-only oracles.

func (l *Ledger) UploadVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	value, err := l.legacyEvidenceCommands().UploadVEX(ctx, actor, releaseID, artifactID, raw)
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadVEXPayload accepts a repeatable pre-hashed payload source for
// streaming HTTP ingestion.
func (l *Ledger) UploadVEXPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.VEXDocument, error) {
	value, err := l.legacyEvidenceCommands().UploadVEXPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

type cycloneDXVEXDocument struct {
	BOMFormat       string                      `json:"bomFormat"`
	SpecVersion     string                      `json:"specVersion"`
	Vulnerabilities []cycloneDXVEXVulnerability `json:"vulnerabilities"`
	Warnings        []string                    `json:"-"`
}

type cycloneDXVEXVulnerability struct {
	ID       string               `json:"id"`
	Affects  []cycloneDXVEXAffect `json:"affects,omitempty"`
	Analysis cycloneDXVEXAnalysis `json:"analysis"`
}

type cycloneDXVEXAffect struct {
	Ref string `json:"ref"`
}

type cycloneDXVEXAnalysis struct {
	State, Justification, Detail string
	Response                     []string
}

func parseCycloneDXVEX(raw []byte) (cycloneDXVEXDocument, error) {
	parsed, err := vexparser.ParseCycloneDX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
	if err != nil {
		return cycloneDXVEXDocument{}, ErrValidation
	}
	doc := cycloneDXVEXDocument{BOMFormat: "CycloneDX", SpecVersion: parsed.Version, Warnings: parsed.Warnings}
	for _, statement := range parsed.Statements {
		vulnerability := cycloneDXVEXVulnerability{ID: statement.Vulnerability, Analysis: cycloneDXVEXAnalysis{Justification: statement.Justification, Detail: statement.ImpactStatement}}
		switch statement.Status {
		case decisionStatusFixed:
			vulnerability.Analysis.State = "resolved"
		case decisionStatusNotAffected:
			vulnerability.Analysis.State = "not_affected"
		case decisionStatusAffected:
			vulnerability.Analysis.State = "exploitable"
		case decisionStatusUnderInvestigation:
			vulnerability.Analysis.State = "in_triage"
		}
		if statement.ActionStatement != "" {
			vulnerability.Analysis.Response = strings.Split(statement.ActionStatement, ",")
		}
		for _, product := range statement.Products {
			vulnerability.Affects = append(vulnerability.Affects, cycloneDXVEXAffect{Ref: product})
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, vulnerability)
	}
	return doc, nil
}

func (l *Ledger) UploadCycloneDXVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	value, err := l.legacyEvidenceCommands().UploadCycloneDXVEX(ctx, actor, releaseID, artifactID, raw)
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

type cycloneDXVEXStatement struct {
	index         int
	vulnerability cycloneDXVEXVulnerability
	status        string
	affectedRefs  map[string]struct{}
}

func analyzeCycloneDXVEXStatements(doc cycloneDXVEXDocument) (map[string]int, []domain.VEXImportIssue, []cycloneDXVEXStatement) {
	statusSummary := map[string]int{}
	invalid := []domain.VEXImportIssue{}
	valid := []cycloneDXVEXStatement{}
	for index, vuln := range doc.Vulnerabilities {
		vuln.ID = strings.TrimSpace(vuln.ID)
		status := cyclonedxAnalysisStatus(vuln.Analysis.State)
		switch {
		case vuln.ID == "":
			invalid = append(invalid, vexImportIssue(index+1, "missing_vulnerability", "CycloneDX VEX vulnerability is missing an id."))
			continue
		case status == "":
			invalid = append(invalid, vexImportIssue(index+1, "unsupported_analysis_state", "CycloneDX VEX vulnerability has an unsupported analysis state."))
			continue
		}
		statusSummary[status]++
		valid = append(valid, cycloneDXVEXStatement{index: index + 1, vulnerability: vuln, status: status, affectedRefs: cycloneDXVEXAffectedRefs(vuln)})
	}
	return statusSummary, invalid, valid
}

func cycloneDXVEXAffectedRefs(vuln cycloneDXVEXVulnerability) map[string]struct{} {
	out := map[string]struct{}{}
	for _, affect := range vuln.Affects {
		if ref := strings.TrimSpace(affect.Ref); ref != "" {
			out[ref] = struct{}{}
		}
	}
	return out
}

func cyclonedxAnalysisStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "resolved":
		return "fixed"
	case "not_affected":
		return "not_affected"
	case "exploitable", "in_triage":
		return "affected"
	default:
		return ""
	}
}
