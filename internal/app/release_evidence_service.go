package app

import (
	"context"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

type releaseEvidenceService struct {
	ledger *Ledger
}

func (l *Ledger) UploadSPDXSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSPDXSBOM(ctx, actor, releaseID, artifactID, raw)
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) releaseEvidenceService() releaseEvidenceService {
	return releaseEvidenceService{ledger: l}
}

func (l *Ledger) CreateProduct(ctx context.Context, actor domain.Actor, name, slug string) (domain.Product, error) {
	value, err := l.releaseCommands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: name, Slug: slug})
	return productFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) ListProducts(ctx context.Context, actor domain.Actor) ([]domain.Product, error) {
	values, err := l.releaseCommands.ListProducts(ctx, actor)
	if err != nil {
		return nil, fromReleaseContextError(err)
	}
	result := make([]domain.Product, 0, len(values))
	for _, value := range values {
		result = append(result, productFromReleaseContext(value))
	}
	return result, nil
}

func (l *Ledger) GetProduct(ctx context.Context, actor domain.Actor, id string) (domain.Product, error) {
	value, err := l.releaseCommands.GetProduct(ctx, actor, id)
	return productFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateProject(ctx context.Context, actor domain.Actor, productID, name string) (domain.Project, error) {
	value, err := l.releaseCommands.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: productID, Name: name})
	return projectFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetProject(ctx context.Context, actor domain.Actor, id string) (domain.Project, error) {
	value, err := l.releaseCommands.GetProject(ctx, actor, id)
	return projectFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateRelease(ctx context.Context, actor domain.Actor, productID, version string) (domain.Release, error) {
	value, err := l.releaseCommands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: productID, Version: version})
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) GetRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	value, err := l.releaseCommands.GetRelease(ctx, actor, releaseID)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) FreezeRelease(ctx context.Context, actor domain.Actor, releaseID string, expectedRevision int64) (domain.Release, error) {
	value, err := l.releaseCommands.FreezeRelease(ctx, actor, releaseID, expectedRevision)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) ApproveRelease(ctx context.Context, actor domain.Actor, releaseID string, expectedRevision int64) (domain.Release, error) {
	value, err := l.releaseCommands.ApproveRelease(ctx, actor, releaseID, expectedRevision)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) RegisterArtifact(ctx context.Context, actor domain.Actor, name, mediaType, digest string, size int64) (domain.Artifact, error) {
	value, err := l.releaseCommands.RegisterArtifact(ctx, actor, releaseapp.RegisterArtifactInput{Name: name, MediaType: mediaType, Digest: digest, Size: size})
	return artifactFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetArtifact(ctx context.Context, actor domain.Actor, id string) (domain.Artifact, error) {
	value, err := l.releaseCommands.GetArtifact(ctx, actor, id)
	return artifactFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateEvidence(ctx context.Context, actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	subjects := make([]evidencedomain.SubjectRef, 0, len(in.SubjectRefs))
	for _, subject := range in.SubjectRefs {
		subjects = append(subjects, evidencedomain.SubjectRef{Type: subject.Type, ID: subject.ID, Digest: subject.Digest})
	}
	value, err := l.evidenceCommands.CreateEvidence(ctx, actor, evidenceapp.CreateEvidenceInput{
		ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID,
		Type: in.Type, Subtype: in.Subtype, Title: in.Title, SourceSystem: in.SourceSystem, SourceIdentity: cloneMap(in.SourceIdentity),
		CollectorID: in.CollectorID, ObservedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash,
		PayloadMediaType: in.PayloadMediaType, PayloadSize: in.PayloadSize, StagedPayload: objectPayloadToEvidenceContext(in.StagedPayload),
		SubjectRefs: subjects, Metadata: cloneMap(in.Metadata), Tags: append([]string(nil), in.Tags...), Limitations: append([]string(nil), in.Limitations...),
	})
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) GetEvidence(ctx context.Context, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	value, err := l.evidenceCommands.GetEvidence(ctx, actor, id)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) ListEvidence(ctx context.Context, actor domain.Actor, releaseID, typ string) ([]domain.EvidenceItem, error) {
	values, err := l.evidenceCommands.ListEvidence(ctx, actor, releaseID, typ)
	if err != nil {
		return nil, fromEvidenceContextError(err)
	}
	result := make([]domain.EvidenceItem, 0, len(values))
	for _, value := range values {
		result = append(result, evidenceFromContext(value))
	}
	return result, nil
}

// ListEvidencePage uses an indexed persistence query when the actor has
// tenant-wide read authority. Granular human grants keep the established
// in-memory authorization path, whose cross-resource grant semantics depend
// on ledger relationship maps.
func (l *Ledger) ListEvidencePage(ctx context.Context, actor domain.Actor, request EvidencePageRequest) (appquery.Result[domain.EvidenceItem], error) {
	if err := ctx.Err(); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if request.TenantID != "" && request.TenantID != actor.TenantID {
		return appquery.Result[domain.EvidenceItem]{}, ErrForbidden
	}
	request.TenantID = actor.TenantID
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	if l.evidencePages != nil && actorHasTenantWideRead(actor, ScopeEvidenceRead) {
		page, err := l.evidencePages.ListEvidencePage(ctx, request)
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validatePagedParserNormalizations(ctx, actor.TenantID, page.Items); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		return page, nil
	}
	items, err := l.ListEvidence(ctx, actor, request.ReleaseID, request.Type)
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	page, err := appquery.Page(items, request.Page, request.After, func(item domain.EvidenceItem, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(item.ID, item.CreatedAt, sort)
	})
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	return page, nil
}

func actorHasTenantWideRead(actor domain.Actor, scope string) bool {
	if !humanSessionActor(actor) {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		if grantHasScope(grant, scope) && (grant.ResourceType == "" || grant.ResourceType == "tenant") && (grant.ResourceID == "" || grant.ResourceID == actor.TenantID) {
			return true
		}
	}
	return false
}

// SearchEvidencePage applies the complete search predicate before paging. It
// does not use EvidenceSearchInput.Limit because cursor page bounds are kept
// separate from matching semantics.
func (l *Ledger) SearchEvidencePage(ctx context.Context, actor domain.Actor, request EvidenceSearchPageRequest) (appquery.Result[domain.EvidenceItem], error) {
	if err := ctx.Err(); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if request.TenantID != "" && request.TenantID != actor.TenantID {
		return appquery.Result[domain.EvidenceItem]{}, ErrForbidden
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	request.TenantID = actor.TenantID
	request.Filter.Limit = 0
	if l.evidencePages != nil && actorHasTenantWideRead(actor, ScopeEvidenceRead) {
		page, err := l.evidencePages.SearchEvidencePage(ctx, request)
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validatePagedParserNormalizations(ctx, actor.TenantID, page.Items); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		return page, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	items := make([]domain.EvidenceItem, 0)
	for _, item := range l.evidence {
		if item.TenantID != actor.TenantID || !matchesEvidenceSearch(item, request.Filter) {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeEvidenceRead, refsForEvidence(item)) {
			continue
		}
		items = append(items, item)
	}
	page, err := appquery.Page(items, request.Page, request.After, func(item domain.EvidenceItem, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(item.ID, item.CreatedAt, sort)
	})
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	return page, nil
}

func (l *Ledger) validatePagedParserNormalizations(ctx context.Context, tenantID string, items []domain.EvidenceItem) error {
	hasParserNormalization := false
	for _, item := range items {
		if item.Type == "parser_normalization" {
			hasParserNormalization = true
			break
		}
	}
	if !hasParserNormalization {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return err
	}
	for _, item := range items {
		if item.Type != "parser_normalization" {
			continue
		}
		cached, ok := l.evidence[item.ID]
		if !ok || cached.TenantID != tenantID || !sameParserNormalizationEvidence(cached, item) {
			return projectionConflict("parser normalization page row")
		}
		source, ok := l.evidence[parserReplayOf(item.Metadata)]
		if !ok {
			return projectionConflict("parser normalization page source")
		}
		var entry domain.AuditChainEntry
		matches := 0
		for _, candidate := range l.chain[tenantID] {
			if candidate.ID == item.ChainEntryID {
				entry = candidate
				matches++
			}
		}
		if matches != 1 {
			return projectionConflict("parser normalization page audit")
		}
		if err := ValidateParserNormalizationRecord(tenantID, item, source, entry); err != nil {
			return err
		}
	}
	return nil
}

func (l *Ledger) SupersedeEvidence(ctx context.Context, actor domain.Actor, id, replacementID, reason string) (domain.EvidenceItem, error) {
	value, err := l.evidenceCommands.SupersedeEvidence(ctx, actor, id, replacementID, reason)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) LinkEvidence(ctx context.Context, actor domain.Actor, id, targetType, targetID string) (domain.EvidenceItem, error) {
	value, err := l.evidenceCommands.LinkEvidence(ctx, actor, id, targetType, targetID)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSBOM(ctx, actor, releaseID, artifactID, raw)
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadSBOMPayload accepts a repeatable pre-hashed payload source for
// streaming HTTP ingestion. CycloneDX 1.6 schema validation and normalization
// consume the same bounded bytes before evidence or object-store side effects.
func (l *Ledger) UploadSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSBOMPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadSPDXSBOMPayload accepts an SPDX JSON source whose bytes are validated,
// normalized, and staged as the same digest-bound payload.
func (l *Ledger) UploadSPDXSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSPDXSBOMPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadVulnerabilityScan(ctx context.Context, actor domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	value, err := l.evidenceCommands.UploadVulnerabilityScan(ctx, actor, raw)
	return vulnerabilityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadVulnerabilityScanPayload accepts a repeatable pre-hashed payload
// source for streaming HTTP ingestion.
func (l *Ledger) UploadVulnerabilityScanPayload(ctx context.Context, actor domain.Actor, source PayloadSource) (domain.VulnerabilityScan, error) {
	value, err := l.evidenceCommands.UploadVulnerabilityScanPayload(ctx, actor, payloadSourceToEvidenceContext(source))
	return vulnerabilityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadOpenAPIContract(ctx context.Context, actor domain.Actor, productID, releaseID, version string, raw []byte) (domain.OpenAPIContract, error) {
	value, err := l.evidenceCommands.UploadOpenAPIContract(ctx, actor, productID, releaseID, version, raw)
	return openAPIContractFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadOpenAPIContractPayload accepts a repeatable pre-hashed payload source
// for streaming HTTP ingestion.
func (l *Ledger) UploadOpenAPIContractPayload(ctx context.Context, actor domain.Actor, productID, releaseID, version string, source PayloadSource) (domain.OpenAPIContract, error) {
	value, err := l.evidenceCommands.UploadOpenAPIContractPayload(ctx, actor, productID, releaseID, version, payloadSourceToEvidenceContext(source))
	return openAPIContractFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) GetSBOM(ctx context.Context, actor domain.Actor, id string) (domain.SBOM, error) {
	return l.releaseEvidenceService().GetSBOM(ctx, actor, id)
}

func (l *Ledger) ListSBOMComponents(ctx context.Context, actor domain.Actor, in ListSBOMComponentsInput) ([]domain.SBOMComponentRecord, error) {
	return l.releaseEvidenceService().ListSBOMComponents(ctx, actor, in)
}

func (l *Ledger) GetVulnerabilityScan(ctx context.Context, actor domain.Actor, id string) (domain.VulnerabilityScan, error) {
	return l.releaseEvidenceService().GetVulnerabilityScan(ctx, actor, id)
}

func (l *Ledger) GetOpenAPIContract(ctx context.Context, actor domain.Actor, id string) (domain.OpenAPIContract, error) {
	return l.releaseEvidenceService().GetOpenAPIContract(ctx, actor, id)
}

func (l *Ledger) UploadVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	value, err := l.evidenceCommands.UploadVEX(ctx, actor, releaseID, artifactID, raw)
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadVEXPayload accepts a repeatable pre-hashed payload source for
// streaming HTTP ingestion.
func (l *Ledger) UploadVEXPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.VEXDocument, error) {
	value, err := l.evidenceCommands.UploadVEXPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) PreviewVEXImport(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXImportPreview, error) {
	return l.releaseEvidenceService().PreviewVEXImport(ctx, actor, releaseID, artifactID, raw)
}

func (l *Ledger) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (domain.VEXDocument, error) {
	return l.releaseEvidenceService().GetVEXDocument(ctx, actor, id)
}

func (l *Ledger) GetVEXImportReport(ctx context.Context, actor domain.Actor, vexID string) (domain.VEXImportReport, error) {
	return l.releaseEvidenceService().GetVEXImportReport(ctx, actor, vexID)
}

func (l *Ledger) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, findingID string, in CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error) {
	return l.releaseEvidenceService().CreateVulnerabilityDecision(ctx, actor, findingID, in)
}

func (l *Ledger) ListVulnerabilityDecisions(ctx context.Context, actor domain.Actor, in ListVulnerabilityDecisionsInput) ([]domain.VulnerabilityDecision, error) {
	return l.releaseEvidenceService().ListVulnerabilityDecisions(ctx, actor, in)
}

func (l *Ledger) VulnerabilityDecisionSummaryReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityDecisionSummaryReport, error) {
	return l.releaseEvidenceService().VulnerabilityDecisionSummaryReport(ctx, actor, releaseID)
}

func (l *Ledger) CreateException(ctx context.Context, actor domain.Actor, in CreateExceptionInput) (domain.Exception, error) {
	return l.releaseEvidenceService().CreateException(ctx, actor, in)
}

func (l *Ledger) ListExceptions(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.Exception, error) {
	return l.releaseEvidenceService().ListExceptions(ctx, actor, releaseID)
}

func (l *Ledger) ApproveException(ctx context.Context, actor domain.Actor, id string) (domain.Exception, error) {
	return l.releaseEvidenceService().ApproveException(ctx, actor, id)
}

func (l *Ledger) ReleaseReadinessReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseReadinessReport, error) {
	return l.releaseEvidenceService().ReleaseReadinessReport(ctx, actor, releaseID)
}
