package wiring

import (
	"time"

	"github.com/aatuh/evydence/internal/app"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func BuildVEXPreviewQuery(reader evidencequery.VEXPreviewReader) (*evidencequery.VEXPreviews, error) {
	return evidencequery.NewVEXPreviews(reader, app.VEXPayloadParser{}, mapVEXPreviewEffects, time.Now)
}

// Explicit read-only cross-context mapping; no Risk repository enters Evidence.
func mapVEXPreviewEffects(format string, p evidenceapp.ParsedVEX, snapshot evidencequery.VEXPreviewSnapshot) (evidencequery.VEXPreviewEffects, error) {
	in := riskapp.VEXDecisionPreviewInput{Format: format, TenantID: snapshot.TenantID, ReleaseID: snapshot.ReleaseID}
	for _, f := range snapshot.Findings {
		in.Findings = append(in.Findings, riskapp.VEXPreviewFinding{VEXFinding: riskapp.VEXFinding{ID: f.ID, ScanID: f.ScanID, TenantID: f.TenantID, ReleaseID: f.ReleaseID, Vulnerability: f.Vulnerability, Component: f.Component}, HasActiveDecision: f.HasActiveDecision})
	}
	for _, s := range p.Statements {
		in.Statements = append(in.Statements, riskapp.VEXStatement{Index: s.StatementIndex, Vulnerability: s.Vulnerability, Products: append([]string(nil), s.Products...), Status: s.Status, Justification: s.Justification, ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement})
	}
	result, err := riskapp.PreviewVEXDecisionEffects(in)
	if err != nil {
		return evidencequery.VEXPreviewEffects{}, evidencequery.ErrConflict
	}
	out := evidencequery.VEXPreviewEffects{WouldCreate: result.WouldCreate, WouldSupersede: result.WouldSupersede, Warnings: result.Warnings, Failures: []evidencedomain.VEXImportIssue{}}
	for _, issue := range result.Failures {
		out.Failures = append(out.Failures, evidencedomain.VEXImportIssue{StatementIndex: issue.StatementIndex, Code: issue.Code, Detail: issue.Detail})
	}
	return out, nil
}
