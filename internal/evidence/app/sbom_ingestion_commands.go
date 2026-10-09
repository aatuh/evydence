package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SBOMIngestionInput struct{ ReleaseID, ArtifactID, Format string }
type SBOMIngestionParser interface {
	ParseSBOM(context.Context, string, PayloadSource) (ParsedSBOM, error)
}
type SBOMIngestionTransaction interface {
	EvidenceCreationTransaction
	InsertSBOM(context.Context, evidencedomain.SBOM) error
}
type SBOMIngestionTransactionRunner interface {
	ExecuteSBOMIngestion(context.Context, func(context.Context, SBOMIngestionTransaction) error) error
}
type SBOMIngestionCommandConfig struct {
	Authorizer              application.Authorizer
	Transactions            SBOMIngestionTransactionRunner
	Parser                  SBOMIngestionParser
	Objects                 SourceObjectIngestion
	Payloads                EvidenceCreationPayloadValidator
	Canonicalizer           Canonicalizer
	CanonicalizationProfile string
	Clock                   application.Clock
	IDs                     application.IDGenerator
	WorkerOwnedParsers      bool
}
type SBOMIngestionCommands struct{ config SBOMIngestionCommandConfig }

func NewSBOMIngestionCommands(c SBOMIngestionCommandConfig) (*SBOMIngestionCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Parser == nil || c.Objects == nil || c.Payloads == nil || c.Canonicalizer == nil || strings.TrimSpace(c.CanonicalizationProfile) == "" || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SBOMIngestionCommands{c}, nil
}
func (c *SBOMIngestionCommands) prepare(ctx context.Context, a identitydomain.Actor, in SBOMIngestionInput) (SBOMIngestionInput, error) {
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
	if in.Format != "cyclonedx" && in.Format != "spdx" {
		return in, ErrValidation
	}
	return in, nil
}
func authorizeSBOMIngestion(ctx context.Context, tx SBOMIngestionTransaction, a identitydomain.Actor, in SBOMIngestionInput) error {
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

// Replay rechecks current release/artifact ownership and grants without parsing.
func (c *SBOMIngestionCommands) AuthorizeUploadSBOM(ctx context.Context, a identitydomain.Actor, in SBOMIngestionInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteSBOMIngestion(ctx, func(ctx context.Context, tx SBOMIngestionTransaction) error {
		return authorizeSBOMIngestion(ctx, tx, a, in)
	})
}
func (c *SBOMIngestionCommands) UploadSBOMPayload(ctx context.Context, a identitydomain.Actor, in SBOMIngestionInput, source PayloadSource) (evidencedomain.SBOM, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	if validatePayloadSource(source) != nil || source.Digest != strings.TrimSpace(source.Digest) {
		return evidencedomain.SBOM{}, ErrValidation
	}
	var sbom evidencedomain.SBOM
	err = c.config.Transactions.ExecuteSBOMIngestion(ctx, func(ctx context.Context, tx SBOMIngestionTransaction) error {
		if err := authorizeSBOMIngestion(ctx, tx, a, in); err != nil {
			return err
		}
		parsed, err := c.config.Parser.ParseSBOM(ctx, in.Format, source)
		if err != nil {
			return err
		}
		parsed.Format, parsed.SpecVersion, parsed.ParserVersion = strings.ToLower(strings.TrimSpace(parsed.Format)), strings.TrimSpace(parsed.SpecVersion), strings.TrimSpace(parsed.ParserVersion)
		if parsed.Format != in.Format || !validDiffText(parsed.SpecVersion, 1024, true) || !validDiffText(parsed.ParserVersion, 1024, true) || !validDiffComponents(parsed.Components) || !validIngestionMetadata(parsed.Metadata, parsed.Limitations) {
			return ErrValidation
		}
		mediaType, title := CycloneDXMediaType, "CycloneDX SBOM"
		if in.Format == "spdx" {
			mediaType, title = SPDXMediaType, "SPDX SBOM"
		}
		staged, err := c.config.Objects.StagePayloadSource(ctx, a.TenantID, mediaType, source)
		if err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
			return ErrValidation
		}
		preparer := evidencePreparer{reader: tx, authorizer: tx, objects: c.config.Payloads, canonicalizer: c.config.Canonicalizer, canonicalizationProfile: strings.TrimSpace(c.config.CanonicalizationProfile), clock: application.ClockFunc(func() time.Time { return now }), ids: c.config.IDs}
		prepared, err := preparer.prepareEvidenceForScope(ctx, a, ScopeEvidenceWrite, CreateEvidenceInput{ReleaseID: in.ReleaseID, Type: "sbom", Subtype: in.Format, Title: title, SourceSystem: "api", ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: source.Digest, PayloadMediaType: mediaType, PayloadSize: source.Size, StagedPayload: staged, SubjectRefs: subjectForArtifact(in.ArtifactID), Metadata: parsed.Metadata, Limitations: parsed.Limitations})
		if err != nil {
			return err
		}
		sbom = evidencedomain.SBOM{ID: c.config.IDs.NewID("sbom"), TenantID: a.TenantID, EvidenceID: prepared.item.ID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Format: in.Format, SpecVersion: parsed.SpecVersion, ComponentCount: len(parsed.Components), Components: append([]evidencedomain.SBOMComponent(nil), parsed.Components...), CreatedAt: now}
		if !validDiffText(sbom.ID, 1024, true) || !validDiffText(sbom.EvidenceID, 1024, true) {
			return ErrValidation
		}
		persisted, action := parserOwnedSBOM(sbom, c.config.WorkerOwnedParsers && staged.Present() && staged.Reference() != "")
		if err := preparer.persistPreparedEvidence(ctx, tx, a, &prepared); err != nil {
			return err
		}
		if err := tx.InsertSBOM(ctx, persisted); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: c.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: action, SubjectType: "sbom", SubjectID: sbom.ID, ActorID: auditActorID(a), ActorType: auditActorType(a), OccurredAt: now, PayloadHash: source.Digest}
		if !validDiffText(audit.ID, 1024, true) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		job := newParserJob(c.config.IDs, a.TenantID, "parse_sbom", "sbom", sbom.ID, source, staged, parsed.ParserVersion, now)
		if !validDiffText(job.ID, 1024, true) {
			return ErrValidation
		}
		return tx.EnqueueOutbox(ctx, job)
	})
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	return cloneSBOM(sbom), nil
}
