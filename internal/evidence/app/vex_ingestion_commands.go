package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const VEXIngestionStatementLimit = 100000
const VEXIngestionStringByteLimit = 1 << 20
const VEXIngestionProjectionByteLimit = 64 << 20
const VEXIngestionDecisionValueLimit = 1000000

type VEXIngestionInput struct{ ReleaseID, ArtifactID, Format string }
type VEXIngestionParser interface {
	ParseVEX(context.Context, string, PayloadSource) (ParsedVEX, error)
}
type VEXIngestionTransaction interface {
	EvidenceCreationTransaction
	InsertVEXDocument(context.Context, evidencedomain.VEXDocument) error
	InsertVEXImportReport(context.Context, evidencedomain.VEXImportReport) error
}
type VEXIngestionTransactionRunner interface {
	ExecuteVEXIngestion(context.Context, func(context.Context, VEXIngestionTransaction) error) error
}
type VEXIngestionCommandConfig struct {
	Authorizer              application.Authorizer
	Transactions            VEXIngestionTransactionRunner
	Parser                  VEXIngestionParser
	Objects                 SourceObjectIngestion
	Payloads                EvidenceCreationPayloadValidator
	Canonicalizer           Canonicalizer
	CanonicalizationProfile string
	Clock                   application.Clock
	IDs                     application.IDGenerator
}
type VEXIngestionCommands struct{ config VEXIngestionCommandConfig }

func NewVEXIngestionCommands(c VEXIngestionCommandConfig) (*VEXIngestionCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Parser == nil || c.Objects == nil || c.Payloads == nil || c.Canonicalizer == nil || strings.TrimSpace(c.CanonicalizationProfile) == "" || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &VEXIngestionCommands{c}, nil
}
func (c *VEXIngestionCommands) prepare(ctx context.Context, a identitydomain.Actor, in VEXIngestionInput) (VEXIngestionInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if err := c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return in, err
	}
	if !validDiffText(a.TenantID, 1024, true) || !validDiffText(auditActorID(a), 1024, true) || !validDiffText(in.ReleaseID, 1024, true) || !validDiffText(in.ArtifactID, 1024, false) || !validDiffText(in.Format, 32, true) {
		return in, ErrValidation
	}
	in.ReleaseID, in.ArtifactID, in.Format = strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.ArtifactID), strings.ToLower(strings.TrimSpace(in.Format))
	if in.Format != "openvex" && in.Format != "cyclonedx" {
		return in, ErrValidation
	}
	return in, nil
}
func authorizeVEXIngestion(ctx context.Context, tx VEXIngestionTransaction, a identitydomain.Actor, in VEXIngestionInput) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	scope := EvidenceScope{ReleaseID: in.ReleaseID}
	if err := tx.ValidateScope(ctx, a.TenantID, scope); err != nil {
		return err
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: resourceReferences(scope)}); err != nil {
		return err
	}
	if in.ArtifactID != "" {
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: in.ArtifactID}}); err != nil {
			return err
		}
		return tx.ValidateArtifactReference(ctx, a.TenantID, in.ArtifactID, "")
	}
	return nil
}

// Replay checks current release/artifact ownership and grants, not VEX bytes.
func (c *VEXIngestionCommands) AuthorizeUploadVEX(ctx context.Context, a identitydomain.Actor, in VEXIngestionInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteVEXIngestion(ctx, func(ctx context.Context, tx VEXIngestionTransaction) error {
		return authorizeVEXIngestion(ctx, tx, a, in)
	})
}

func validVEXIngestionProjection(p ParsedVEX, format string) bool {
	if p.StatementCount <= 0 || p.StatementCount > VEXIngestionStatementLimit || len(p.Statements) > VEXIngestionStatementLimit || len(p.InvalidStatements) > VEXIngestionStatementLimit || len(p.Warnings) > VEXIngestionStatementLimit || len(p.Limitations) > VEXIngestionStatementLimit || !validIngestionMetadata(p.Metadata, p.Limitations) {
		return false
	}
	remaining := VEXIngestionProjectionByteLimit
	bounded := func(s string, required bool) bool {
		if !validDiffText(s, VEXIngestionStringByteLimit, required) || len(s) > remaining {
			return false
		}
		remaining -= len(s)
		return true
	}
	if !bounded(p.Author, format == "openvex") || !bounded(p.Version, format == "cyclonedx") {
		return false
	}
	for _, values := range [][]string{p.Warnings, p.Limitations} {
		for _, s := range values {
			if !bounded(s, false) {
				return false
			}
		}
	}
	for _, issue := range p.InvalidStatements {
		if !bounded(issue.Code, true) || !bounded(issue.Detail, true) {
			return false
		}
	}
	values, textBytes := 0, int64(0)
	for _, s := range p.Statements {
		if len(s.Products) > VEXIngestionStatementLimit {
			return false
		}
		values += 7 + len(s.Products)
		if values > VEXIngestionDecisionValueLimit {
			return false
		}
		for i, text := range []string{s.Vulnerability, s.Status, s.Justification, s.ImpactStatement, s.ActionStatement} {
			if !bounded(text, i < 2) {
				return false
			}
			textBytes += int64(len(text))
		}
		for _, product := range s.Products {
			if !bounded(product, true) {
				return false
			}
			textBytes += int64(len(product))
		}
		// Match the worker's normalized decision-request text budget. A source
		// may expand references during normalization; reject, never truncate.
		if textBytes > EvidenceDocumentLimit {
			return false
		}
	}
	return validateParsedVEX(p, format) == nil
}

func (c *VEXIngestionCommands) UploadVEXPayload(ctx context.Context, a identitydomain.Actor, in VEXIngestionInput, source PayloadSource) (evidencedomain.VEXDocument, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	if validatePayloadSource(source) != nil || source.Digest != strings.TrimSpace(source.Digest) {
		return evidencedomain.VEXDocument{}, ErrValidation
	}
	var result evidencedomain.VEXDocument
	err = c.config.Transactions.ExecuteVEXIngestion(ctx, func(ctx context.Context, tx VEXIngestionTransaction) error {
		if err := authorizeVEXIngestion(ctx, tx, a, in); err != nil {
			return err
		}
		parsed, err := c.config.Parser.ParseVEX(ctx, in.Format, source)
		if err != nil {
			return err
		}
		parsed.Format, parsed.Author, parsed.Version, parsed.ParserVersion = strings.ToLower(strings.TrimSpace(parsed.Format)), strings.TrimSpace(parsed.Author), strings.TrimSpace(parsed.Version), strings.TrimSpace(parsed.ParserVersion)
		if !validVEXIngestionProjection(parsed, in.Format) {
			return ErrValidation
		}
		media, title := OpenVEXMediaType, "OpenVEX document"
		if in.Format == "cyclonedx" {
			media, title = CycloneDXMediaType, "CycloneDX VEX"
		}
		staged, err := c.config.Objects.StagePayloadSource(ctx, a.TenantID, media, source)
		if err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
			return ErrValidation
		}
		preparer := evidencePreparer{reader: tx, authorizer: tx, objects: c.config.Payloads, canonicalizer: c.config.Canonicalizer, canonicalizationProfile: strings.TrimSpace(c.config.CanonicalizationProfile), clock: application.ClockFunc(func() time.Time { return now }), ids: c.config.IDs}
		prepared, err := preparer.prepareEvidenceForScope(ctx, a, ScopeEvidenceWrite, CreateEvidenceInput{ReleaseID: in.ReleaseID, Type: "vex", Subtype: in.Format, Title: title, SourceSystem: "api", ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: source.Digest, PayloadMediaType: media, PayloadSize: source.Size, StagedPayload: staged, SubjectRefs: subjectForArtifact(in.ArtifactID), Metadata: parsed.Metadata, Limitations: parsed.Limitations})
		if err != nil {
			return err
		}
		vex, report, job := buildVEXIngestionRecords(c.config.IDs, a, in, parsed, prepared.item.ID, source, staged, now)
		for _, id := range []string{vex.ID, vex.EvidenceID, report.ID, job.ID} {
			if !validDiffText(id, 1024, true) {
				return ErrValidation
			}
		}
		if err := preparer.persistPreparedEvidence(ctx, tx, a, &prepared); err != nil {
			return err
		}
		if err := tx.InsertVEXDocument(ctx, vex); err != nil {
			return err
		}
		if err := tx.InsertVEXImportReport(ctx, report); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: c.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "vex.accepted", SubjectType: "vex_document", SubjectID: vex.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now, PayloadHash: source.Digest}
		if !validDiffText(audit.ID, 1024, true) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		if err := tx.EnqueueOutbox(ctx, job); err != nil {
			return err
		}
		result = vex
		return nil
	})
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	return cloneVEXDocument(result), nil
}

// Shared by the focused command and existing explicit compatibility service.
// This is the single producer of the worker's versioned decision request.
func buildVEXIngestionRecords(ids application.IDGenerator, a identitydomain.Actor, in VEXIngestionInput, p ParsedVEX, evidenceID string, source PayloadSource, staged StagedPayload, now time.Time) (evidencedomain.VEXDocument, evidencedomain.VEXImportReport, application.OutboxEvent) {
	vex := evidencedomain.VEXDocument{ID: ids.NewID("vex"), TenantID: a.TenantID, EvidenceID: evidenceID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Format: in.Format, Author: p.Author, Version: p.Version, StatementCount: p.StatementCount, StatusSummary: cloneIntMap(p.StatusSummary), SchemaVersion: evidencedomain.VEXDocumentSchemaVersion, CreatedAt: now}
	report := evidencedomain.VEXImportReport{ID: ids.NewID("vexrep"), TenantID: a.TenantID, VEXDocumentID: vex.ID, EvidenceID: vex.EvidenceID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, ParserVersion: p.ParserVersion, Status: "accepted", StatementCount: p.StatementCount, UnsupportedFields: []string{}, Warnings: appendUniqueString(append([]string(nil), p.Warnings...), VEXAsyncDecisionWarning), InvalidStatements: cloneVEXImportIssues(p.InvalidStatements), MappingFailures: []evidencedomain.VEXImportIssue{}, SchemaVersion: evidencedomain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now}
	job := newParserJob(ids, a.TenantID, "parse_vex", "vex_document", vex.ID, source, staged, p.ParserVersion, now)
	job.Payload["worker_create_decisions"] = true
	job.Payload["decision_request_schema"] = VEXDecisionRequestSchemaVersion
	job.Payload["decision_statements"] = vexDecisionStatementsPayload(p.Statements)
	job.Payload["actor_type"], job.Payload["actor_id"] = auditActorType(a), auditActorID(a)
	job.Payload["evidence_id"], job.Payload["release_id"], job.Payload["artifact_id"] = vex.EvidenceID, vex.ReleaseID, vex.ArtifactID
	job.Payload["import_report_id"], job.Payload["decisions_created"] = report.ID, 0
	return vex, report, job
}
