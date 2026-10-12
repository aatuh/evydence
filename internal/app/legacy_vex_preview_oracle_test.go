package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical preview algorithms are unchanged test-only behavior oracles.
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

func (l *Ledger) PreviewCycloneDXVEXImport(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXImportPreview, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if !ValidPayloadSize(int64(len(raw)), EvidenceDocumentLimit) {
		return domain.VEXImportPreview{}, ErrValidation
	}
	doc, err := parseCycloneDXVEX(raw)
	if err != nil || len(doc.Vulnerabilities) == 0 {
		return domain.VEXImportPreview{}, ErrValidation
	}
	statusSummary, invalidStatements, validStatements := analyzeCycloneDXVEXStatements(doc)
	if len(validStatements) == 0 {
		return domain.VEXImportPreview{}, ErrValidation
	}
	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
	if releaseID == "" {
		return domain.VEXImportPreview{}, ErrValidation
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
	created, superseded, warnings, mappingFailures := l.previewCycloneDXVEXDecisionEffectsLocked(actor.TenantID, releaseID, validStatements)
	warnings = append(append([]string{}, doc.Warnings...), warnings...)
	if len(invalidStatements) > 0 {
		warnings = append(warnings, "One or more CycloneDX VEX vulnerabilities were skipped because required analysis fields were missing or unsupported.")
	}
	return domain.VEXImportPreview{
		TenantID:                actor.TenantID,
		ReleaseID:               releaseID,
		ArtifactID:              artifactID,
		Format:                  "cyclonedx",
		ParserVersion:           ParserVersionCycloneDXVEXJSON,
		Advisory:                true,
		StatementCount:          len(doc.Vulnerabilities),
		StatusSummary:           cloneIntMap(statusSummary),
		DecisionsWouldCreate:    created,
		DecisionsWouldSupersede: superseded,
		Warnings:                warnings,
		InvalidStatements:       invalidStatements,
		MappingFailures:         mappingFailures,
		Assumptions:             vexImportPreviewAssumptions(),
		Limitations:             vexImportPreviewLimitations(),
		SchemaVersion:           domain.VEXImportPreviewSchemaVersion,
		GeneratedAt:             l.now(),
	}, nil
}

func (l *Ledger) findCycloneDXVEXMatchingFindingsLocked(tenantID, releaseID string, statement cycloneDXVEXStatement) ([]matchedFinding, bool) {
	out := []matchedFinding{}
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		for _, finding := range scan.Findings {
			if finding.Vulnerability != statement.vulnerability.ID {
				continue
			}
			if len(statement.affectedRefs) > 0 && finding.Component != "" {
				if _, ok := statement.affectedRefs[finding.Component]; !ok {
					continue
				}
			}
			out = append(out, matchedFinding{scan: scan, finding: finding})
		}
	}
	return unambiguousVEXMatches(out, statement.affectedRefs)
}

func (l *Ledger) previewCycloneDXVEXDecisionEffectsLocked(tenantID, releaseID string, statements []cycloneDXVEXStatement) (int, int, []string, []domain.VEXImportIssue) {
	created, superseded := 0, 0
	mappingFailures := []domain.VEXImportIssue{}
	warnings := []string{}
	createdForFinding := map[string]struct{}{}
	duplicateWarningAdded := false
	for _, statement := range statements {
		matches, ambiguous := l.findCycloneDXVEXMatchingFindingsLocked(tenantID, releaseID, statement)
		if ambiguous {
			mappingFailures = append(mappingFailures, vexImportIssue(statement.index, "ambiguous_finding", "Multiple plausible findings matched this CycloneDX VEX vulnerability; no decision would be applied."))
			continue
		}
		if len(matches) == 0 {
			mappingFailures = append(mappingFailures, vexImportIssue(statement.index, "finding_not_found", "No matching vulnerability scan finding was found for this CycloneDX VEX vulnerability."))
		}
		added, replaced, duplicate := l.previewDecisionEffectsForMatchesLocked(tenantID, matches, createdForFinding)
		created += added
		superseded += replaced
		if duplicate && !duplicateWarningAdded {
			warnings = append(warnings, "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored.")
			duplicateWarningAdded = true
		}
	}
	return created, superseded, warnings, mappingFailures
}
