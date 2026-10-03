package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const (
	VEXAsyncDecisionWarning         = "VEX decisions are created asynchronously from a versioned normalized request after the evidence transaction commits."
	VEXDecisionRequestSchemaVersion = "vex-decision-request.v1.0.0"
)

func (s *Service) UploadVEX(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, raw []byte) (evidencedomain.VEXDocument, error) {
	return s.UploadVEXPayload(ctx, actor, releaseID, artifactID, BytesPayloadSource(raw))
}

func (s *Service) UploadVEXPayload(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, source PayloadSource) (evidencedomain.VEXDocument, error) {
	return s.uploadVEXPayload(ctx, actor, releaseID, artifactID, "openvex", "openvex", "OpenVEX document", OpenVEXMediaType, source)
}

func (s *Service) UploadCycloneDXVEX(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, raw []byte) (evidencedomain.VEXDocument, error) {
	return s.uploadVEXPayload(ctx, actor, releaseID, artifactID, "cyclonedx", "cyclonedx", "CycloneDX VEX", CycloneDXMediaType, BytesPayloadSource(raw))
}

func (s *Service) uploadVEXPayload(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID, format, subtype, title, mediaType string, source PayloadSource) (evidencedomain.VEXDocument, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
	if releaseID == "" || validatePayloadSource(source) != nil {
		return evidencedomain.VEXDocument{}, ErrValidation
	}
	scope := EvidenceScope{ReleaseID: releaseID}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, resourceReferences(scope), false); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	if err := s.validateAndAuthorizeArtifactReference(ctx, actor, ScopeEvidenceWrite, artifactID, ""); err != nil {
		return evidencedomain.VEXDocument{}, err
	}

	parsed, err := s.parser.ParseVEX(ctx, format, source)
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	parsed.Format = strings.ToLower(strings.TrimSpace(parsed.Format))
	parsed.Author = strings.TrimSpace(parsed.Author)
	parsed.Version = strings.TrimSpace(parsed.Version)
	parsed.ParserVersion = strings.TrimSpace(parsed.ParserVersion)
	if err := validateParsedVEX(parsed, format); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	staged, err := s.sourceObjects.StagePayloadSource(ctx, actor.TenantID, mediaType, source)
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	limitations := append([]string(nil), parsed.Limitations...)

	now := s.clock.Now().UTC()
	prepared, err := s.prepareEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID: releaseID, Type: "vex", Subtype: subtype, Title: title, SourceSystem: "api", ObservedAt: now,
		PayloadRef: staged.Reference(), PayloadHash: source.Digest, PayloadMediaType: mediaType, PayloadSize: source.Size,
		StagedPayload: staged, SubjectRefs: subjectForArtifact(artifactID), Metadata: cloneMap(parsed.Metadata), Limitations: limitations,
	})
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	vex, report, job := buildVEXIngestionRecords(s.ids, actor, VEXIngestionInput{ReleaseID: releaseID, ArtifactID: artifactID, Format: format}, parsed, prepared.item.ID, source, staged, now)

	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := s.persistPreparedEvidence(ctx, tx, actor, &prepared); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertVEXDocument(ctx, vex); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertVEXImportReport(ctx, report); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, now, "vex.accepted", "vex_document", vex.ID, source.Digest)); err != nil {
			return err
		}
		return tx.Outbox().EnqueueOutbox(ctx, job)
	})
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	return cloneVEXDocument(vex), nil
}

func validateParsedVEX(parsed ParsedVEX, expectedFormat string) error {
	expectedParserVersion := OpenVEXParserVersion
	if expectedFormat == "cyclonedx" {
		expectedParserVersion = CycloneDXVEXParserVersion
	}
	if parsed.Format != expectedFormat || parsed.ParserVersion != expectedParserVersion || parsed.StatementCount <= 0 || parsed.ValidStatementCount <= 0 || parsed.ValidStatementCount > parsed.StatementCount || len(parsed.Statements) != parsed.ValidStatementCount {
		return ErrValidation
	}
	if expectedFormat == "openvex" && parsed.Author == "" {
		return ErrValidation
	}
	if expectedFormat == "cyclonedx" && parsed.Version == "" {
		return ErrValidation
	}
	statusCount := 0
	for status, count := range parsed.StatusSummary {
		switch status {
		case "affected", "not_affected", "fixed", "under_investigation":
		default:
			return ErrValidation
		}
		if count < 0 {
			return ErrValidation
		}
		statusCount += count
	}
	if statusCount != parsed.ValidStatementCount || len(parsed.InvalidStatements) != parsed.StatementCount-parsed.ValidStatementCount {
		return ErrValidation
	}
	seenIndexes := map[int]struct{}{}
	statementSummary := map[string]int{}
	for _, statement := range parsed.Statements {
		statement.Vulnerability = strings.TrimSpace(statement.Vulnerability)
		statement.Status = strings.TrimSpace(statement.Status)
		if statement.StatementIndex <= 0 || statement.StatementIndex > parsed.StatementCount || statement.Vulnerability == "" || !validVEXStatus(statement.Status) {
			return ErrValidation
		}
		if _, duplicate := seenIndexes[statement.StatementIndex]; duplicate {
			return ErrValidation
		}
		seenIndexes[statement.StatementIndex] = struct{}{}
		seenProducts := map[string]struct{}{}
		for _, product := range statement.Products {
			product = strings.TrimSpace(product)
			if product == "" {
				return ErrValidation
			}
			if _, duplicate := seenProducts[product]; duplicate {
				return ErrValidation
			}
			seenProducts[product] = struct{}{}
		}
		if expectedFormat == "openvex" && len(seenProducts) == 0 {
			return ErrValidation
		}
		statementSummary[statement.Status]++
	}
	if len(statementSummary) != len(parsed.StatusSummary) {
		return ErrValidation
	}
	for status, count := range statementSummary {
		if parsed.StatusSummary[status] != count {
			return ErrValidation
		}
	}
	for _, issue := range parsed.InvalidStatements {
		if issue.StatementIndex <= 0 || issue.StatementIndex > parsed.StatementCount || strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Detail) == "" {
			return ErrValidation
		}
		if _, duplicate := seenIndexes[issue.StatementIndex]; duplicate {
			return ErrValidation
		}
		seenIndexes[issue.StatementIndex] = struct{}{}
	}
	if len(seenIndexes) != parsed.StatementCount {
		return ErrValidation
	}
	return nil
}

func validVEXStatus(status string) bool {
	switch status {
	case "affected", "not_affected", "fixed", "under_investigation":
		return true
	default:
		return false
	}
}

func cloneVEXDocument(value evidencedomain.VEXDocument) evidencedomain.VEXDocument {
	value.StatusSummary = cloneIntMap(value.StatusSummary)
	return value
}

func cloneVEXImportReport(value evidencedomain.VEXImportReport) evidencedomain.VEXImportReport {
	value.UnsupportedFields = append([]string(nil), value.UnsupportedFields...)
	value.Warnings = append([]string(nil), value.Warnings...)
	value.InvalidStatements = cloneVEXImportIssues(value.InvalidStatements)
	value.MappingFailures = cloneVEXImportIssues(value.MappingFailures)
	return value
}

func cloneVEXImportIssues(values []evidencedomain.VEXImportIssue) []evidencedomain.VEXImportIssue {
	return append([]evidencedomain.VEXImportIssue(nil), values...)
}

func vexDecisionStatementsPayload(values []VEXDecisionStatement) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"statement_index":  value.StatementIndex,
			"vulnerability":    value.Vulnerability,
			"products":         append([]string(nil), value.Products...),
			"status":           value.Status,
			"justification":    value.Justification,
			"impact_statement": value.ImpactStatement,
			"action_statement": value.ActionStatement,
		})
	}
	return result
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
