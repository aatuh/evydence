package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type OpenAPIIngestionInput struct{ ProductID, ReleaseID, Version string }
type OpenAPIIngestionParser interface {
	ParseOpenAPIContract(context.Context, PayloadSource) (ParsedOpenAPIContract, error)
}
type OpenAPIIngestionTransaction interface {
	EvidenceCreationTransaction
	InsertOpenAPIContract(context.Context, evidencedomain.OpenAPIContract) error
}
type OpenAPIIngestionTransactionRunner interface {
	ExecuteOpenAPIIngestion(context.Context, func(context.Context, OpenAPIIngestionTransaction) error) error
}
type OpenAPIIngestionCommandConfig struct {
	Authorizer              application.Authorizer
	Transactions            OpenAPIIngestionTransactionRunner
	Parser                  OpenAPIIngestionParser
	Objects                 SourceObjectIngestion
	Payloads                EvidenceCreationPayloadValidator
	Canonicalizer           Canonicalizer
	CanonicalizationProfile string
	Clock                   application.Clock
	IDs                     application.IDGenerator
	WorkerOwnedParsers      bool
}
type OpenAPIIngestionCommands struct{ config OpenAPIIngestionCommandConfig }

func NewOpenAPIIngestionCommands(c OpenAPIIngestionCommandConfig) (*OpenAPIIngestionCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Parser == nil || c.Objects == nil || c.Payloads == nil || c.Canonicalizer == nil || strings.TrimSpace(c.CanonicalizationProfile) == "" || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &OpenAPIIngestionCommands{c}, nil
}
func (c *OpenAPIIngestionCommands) prepare(ctx context.Context, a identitydomain.Actor, in OpenAPIIngestionInput) (OpenAPIIngestionInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if err := c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return in, err
	}
	if !validDiffText(a.TenantID, 1024, true) || !validDiffText(auditActorID(a), 1024, true) || !validDiffText(in.ProductID, 1024, true) || !validDiffText(in.ReleaseID, 1024, false) || !validDiffText(in.Version, 65536, true) {
		return in, ErrValidation
	}
	in.ProductID = strings.TrimSpace(in.ProductID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.Version = strings.TrimSpace(in.Version)
	return in, nil
}
func authorizeOpenAPIIngestion(ctx context.Context, tx OpenAPIIngestionTransaction, a identitydomain.Actor, in OpenAPIIngestionInput) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	scope := EvidenceScope{ProductID: in.ProductID, ReleaseID: in.ReleaseID}
	if err := tx.ValidateScope(ctx, a.TenantID, scope); err != nil {
		return err
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: resourceReferences(scope)})
}

// Replay checks current ownership and grants, never a parser or object store.
func (c *OpenAPIIngestionCommands) AuthorizeUploadOpenAPIContract(ctx context.Context, a identitydomain.Actor, in OpenAPIIngestionInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteOpenAPIIngestion(ctx, func(ctx context.Context, tx OpenAPIIngestionTransaction) error {
		return authorizeOpenAPIIngestion(ctx, tx, a, in)
	})
}
func (c *OpenAPIIngestionCommands) UploadOpenAPIContractPayload(ctx context.Context, a identitydomain.Actor, in OpenAPIIngestionInput, source PayloadSource) (evidencedomain.OpenAPIContract, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	if validatePayloadSource(source) != nil || source.Digest != strings.TrimSpace(source.Digest) {
		return evidencedomain.OpenAPIContract{}, ErrValidation
	}
	var contract evidencedomain.OpenAPIContract
	err = c.config.Transactions.ExecuteOpenAPIIngestion(ctx, func(ctx context.Context, tx OpenAPIIngestionTransaction) error {
		if err := authorizeOpenAPIIngestion(ctx, tx, a, in); err != nil {
			return err
		}
		parsed, err := c.config.Parser.ParseOpenAPIContract(ctx, source)
		if err != nil {
			return err
		}
		parsed.ParserVersion = strings.TrimSpace(parsed.ParserVersion)
		parsed.SourceSchema = strings.TrimSpace(parsed.SourceSchema)
		if !validDiffText(parsed.ParserVersion, 1024, true) || !validDiffText(parsed.SourceSchema, 1024, true) || !validContractDiffProjection(evidencedomain.OpenAPIContract{Hash: source.Digest, PathCount: parsed.PathCount, Operations: parsed.Operations}) {
			return ErrValidation
		}
		// Validate before deep-copying parser metadata; a cyclic or unsupported
		// value must not enter canonicalization or durable evidence.
		if !validIngestionMetadata(parsed.Metadata, parsed.Limitations) {
			return ErrValidation
		}
		staged, err := c.config.Objects.StagePayloadSource(ctx, a.TenantID, OpenAPIMediaType, source)
		if err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
			return ErrValidation
		}
		preparer := evidencePreparer{reader: tx, authorizer: tx, objects: c.config.Payloads, canonicalizer: c.config.Canonicalizer, canonicalizationProfile: strings.TrimSpace(c.config.CanonicalizationProfile), clock: application.ClockFunc(func() time.Time { return now }), ids: c.config.IDs}
		prepared, err := preparer.prepareEvidenceForScope(ctx, a, ScopeEvidenceWrite, CreateEvidenceInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID, Type: "openapi_contract", Subtype: "openapi", Title: "OpenAPI contract", SourceSystem: "api", ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: source.Digest, PayloadMediaType: OpenAPIMediaType, PayloadSize: source.Size, StagedPayload: staged, Metadata: parsed.Metadata, Limitations: parsed.Limitations})
		if err != nil {
			return err
		}
		contract = evidencedomain.OpenAPIContract{ID: c.config.IDs.NewID("oas"), TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Version: in.Version, Hash: source.Digest, PathCount: parsed.PathCount, Operations: cloneOpenAPIOperations(parsed.Operations), EvidenceID: prepared.item.ID, CreatedAt: now}
		if !validDiffText(contract.ID, 1024, true) || !validDiffText(contract.EvidenceID, 1024, true) {
			return ErrValidation
		}
		persisted, action := parserOwnedOpenAPIContract(contract, c.config.WorkerOwnedParsers && staged.Present() && staged.Reference() != "")
		if err := preparer.persistPreparedEvidence(ctx, tx, a, &prepared); err != nil {
			return err
		}
		if err := tx.InsertOpenAPIContract(ctx, persisted); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: c.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: action, SubjectType: "openapi_contract", SubjectID: contract.ID, ActorID: auditActorID(a), ActorType: auditActorType(a), OccurredAt: now, PayloadHash: source.Digest}
		if !validDiffText(audit.ID, 1024, true) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		job := newParserJob(c.config.IDs, a.TenantID, "parse_openapi_contract", "openapi_contract", contract.ID, source, staged, parsed.ParserVersion, now)
		if !validDiffText(job.ID, 1024, true) {
			return ErrValidation
		}
		return tx.EnqueueOutbox(ctx, job)
	})
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	return cloneOpenAPIContract(contract), nil
}
