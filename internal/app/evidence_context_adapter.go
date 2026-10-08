package app

import (
	"context"
	"errors"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

func (l *Ledger) configureEvidenceCommands() error {
	parser := ledgerEvidencePayloadParser{}
	service, err := evidenceapp.NewService(evidenceapp.Config{
		Reader: ledgerEvidenceReader{ledger: l}, Transactions: ledgerEvidenceTransactions{ledger: l},
		ProjectionRefresher: ledgerEvidenceProjectionRefresher{ledger: l},
		Authorizer:          ledgerContextAuthorizer{ledger: l}, Objects: ledgerEvidenceObjectIngestion{ledger: l},
		SourceObjects: ledgerEvidenceSourceObjectIngestion{ledger: l}, Parser: parser, VulnerabilityScanScopeProber: parser,
		Canonicalizer: ledgerEvidenceCanonicalizer{}, LifecycleSanitizer: ledgerEvidenceLifecycleSanitizer{}, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion,
		Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID),
		WorkerOwnedParsers: l.workerOwnedParsers,
	})
	if err != nil {
		return err
	}
	l.evidenceCommands = service
	return nil
}

type ledgerEvidenceProjectionRefresher struct{ ledger *Ledger }

func (r ledgerEvidenceProjectionRefresher) RefreshWorkerProjection(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return toEvidenceContextError(r.ledger.refreshWorkerProjectionLocked(ctx, tenantID))
}

type ledgerEvidenceObjectIngestion struct{ ledger *Ledger }

func (v ledgerEvidenceObjectIngestion) StagePayload(ctx context.Context, tenantID, mediaType, digest string, raw []byte) (evidenceapp.StagedPayload, error) {
	payload, err := v.ledger.stagePayload(ctx, tenantID, mediaType, digest, raw)
	if err != nil {
		return evidenceapp.StagedPayload{}, toEvidenceContextError(err)
	}
	return objectPayloadToEvidenceContext(payload), nil
}

func (v ledgerEvidenceObjectIngestion) ValidateStagedPayload(_ context.Context, payload evidenceapp.StagedPayload) error {
	if err := validateObjectPayload(objectPayloadFromEvidenceContext(payload)); err != nil {
		return evidenceapp.ErrValidation
	}
	if (v.ledger.unitOfWork != nil && payload.Status != evidenceapp.PayloadStatusStaged) || (v.ledger.unitOfWork == nil && payload.Status != evidenceapp.PayloadStatusFinalized) {
		return evidenceapp.ErrValidation
	}
	return nil
}

type ledgerEvidenceLifecycleSanitizer struct{}

func (ledgerEvidenceLifecycleSanitizer) SanitizeLifecycle(_ context.Context, reason string, details map[string]any) (string, map[string]any, error) {
	safeDetails, _ := redaction.RemoveSensitive(details)
	result, _ := safeDetails.(map[string]any)
	return redaction.RedactString(reason), result, nil
}

type ledgerEvidenceCanonicalizer struct{}

func (ledgerEvidenceCanonicalizer) HashEvidence(_ context.Context, item evidencedomain.EvidenceItem) (string, error) {
	return canonicalHash(evidenceFromContext(item))
}

type ledgerEvidenceReader struct{ ledger *Ledger }

func (r ledgerEvidenceReader) ValidateScope(ctx context.Context, tenantID string, scope evidenceapp.EvidenceScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return toEvidenceContextError(validateLedgerEvidenceScopeLocked(r.ledger, tenantID, scope))
}

func validateLedgerEvidenceScopeLocked(ledger *Ledger, tenantID string, scope evidenceapp.EvidenceScope) error {
	if _, ok := ledger.tenants[strings.TrimSpace(tenantID)]; !ok {
		return ErrNotFound
	}
	scope.ProductID = strings.TrimSpace(scope.ProductID)
	scope.ProjectID = strings.TrimSpace(scope.ProjectID)
	scope.ReleaseID = strings.TrimSpace(scope.ReleaseID)
	scope.BuildID = strings.TrimSpace(scope.BuildID)
	scope.DeploymentID = strings.TrimSpace(scope.DeploymentID)
	if scope.ProductID != "" {
		product, ok := ledger.products[scope.ProductID]
		if !ok || product.TenantID != tenantID {
			return ErrNotFound
		}
	}
	var project domain.Project
	if scope.ProjectID != "" {
		var ok bool
		project, ok = ledger.projects[scope.ProjectID]
		if !ok || project.TenantID != tenantID || (scope.ProductID != "" && project.ProductID != scope.ProductID) {
			return ErrNotFound
		}
	}
	if scope.ReleaseID != "" {
		release, ok := ledger.releases[scope.ReleaseID]
		if !ok || release.TenantID != tenantID || (scope.ProductID != "" && release.ProductID != scope.ProductID) || (scope.ProjectID != "" && release.ProductID != project.ProductID) {
			return ErrNotFound
		}
	}
	var build domain.BuildRun
	if scope.BuildID != "" {
		var ok bool
		build, ok = ledger.buildRuns[scope.BuildID]
		if !ok || build.TenantID != tenantID || (scope.ProjectID != "" && build.ProjectID != scope.ProjectID) || (scope.ReleaseID != "" && build.ReleaseID != scope.ReleaseID) {
			return ErrNotFound
		}
		buildProject, projectOK := ledger.projects[build.ProjectID]
		buildRelease, releaseOK := ledger.releases[build.ReleaseID]
		if !projectOK || !releaseOK || buildProject.TenantID != tenantID || buildRelease.TenantID != tenantID || buildProject.ProductID != buildRelease.ProductID || (scope.ProductID != "" && buildProject.ProductID != scope.ProductID) {
			return ErrNotFound
		}
	}
	if scope.DeploymentID != "" {
		deployment, ok := ledger.deployments[scope.DeploymentID]
		if !ok && scope.AllowPendingDeployment {
			return nil
		}
		if !ok || deployment.TenantID != tenantID || (scope.ReleaseID != "" && deployment.ReleaseID != scope.ReleaseID) || (scope.BuildID != "" && deployment.ReleaseID != build.ReleaseID) {
			return ErrNotFound
		}
		environment, environmentOK := ledger.environments[deployment.EnvironmentID]
		deploymentRelease, releaseOK := ledger.releases[deployment.ReleaseID]
		if !environmentOK || !releaseOK || environment.TenantID != tenantID || deploymentRelease.TenantID != tenantID || environment.ProductID != deploymentRelease.ProductID || (scope.ProductID != "" && environment.ProductID != scope.ProductID) || (scope.ProjectID != "" && project.ProductID != environment.ProductID) {
			return ErrNotFound
		}
	}
	return nil
}

func (r ledgerEvidenceReader) ValidateLinkTarget(ctx context.Context, tenantID, targetType, targetID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return validateEvidenceLinkTarget(r.ledger, tenantID, targetType, targetID)
}

func (r ledgerEvidenceReader) ValidateArtifactReference(ctx context.Context, tenantID, artifactID, digest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	artifactID = strings.TrimSpace(artifactID)
	if artifactID == "" {
		return nil
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	artifact, ok := r.ledger.artifacts[artifactID]
	if !ok || artifact.TenantID != tenantID || (digest != "" && !strings.EqualFold(artifact.Digest, digest)) {
		return evidenceapp.ErrNotFound
	}
	return nil
}

func (r ledgerEvidenceReader) GetEvidence(ctx context.Context, tenantID, id string) (evidencedomain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return evidencedomain.EvidenceItem{}, toEvidenceContextError(err)
	}
	item, ok := r.ledger.evidence[strings.TrimSpace(id)]
	if !ok || item.TenantID != tenantID {
		return evidencedomain.EvidenceItem{}, evidenceapp.ErrNotFound
	}
	return evidenceToContext(item), nil
}

func (r ledgerEvidenceReader) GetSBOM(ctx context.Context, tenantID, id string) (evidencedomain.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return evidencedomain.SBOM{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	value, ok := r.ledger.sboms[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.SBOM{}, evidenceapp.ErrNotFound
	}
	return sbomToEvidenceContext(value), nil
}

func (r ledgerEvidenceReader) GetOpenAPIContract(ctx context.Context, tenantID, id string) (evidencedomain.OpenAPIContract, error) {
	if err := ctx.Err(); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	if r.ledger.unitOfWork != nil {
		var value domain.OpenAPIContract
		err := r.ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			var err error
			value, err = repositories.Evidence.GetOpenAPIContract(ctx, tenantID, strings.TrimSpace(id))
			return err
		})
		if err != nil {
			return evidencedomain.OpenAPIContract{}, toEvidenceContextError(err)
		}
		return openAPIContractToEvidenceContext(value), nil
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	value, ok := r.ledger.contracts[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.OpenAPIContract{}, evidenceapp.ErrNotFound
	}
	return openAPIContractToEvidenceContext(value), nil
}

func (r ledgerEvidenceReader) ListEvidence(ctx context.Context, tenantID, releaseID, evidenceType string) ([]evidencedomain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return nil, toEvidenceContextError(err)
	}
	result := make([]evidencedomain.EvidenceItem, 0)
	for _, item := range r.ledger.evidence {
		if item.TenantID != tenantID || (releaseID != "" && item.ReleaseID != releaseID) || (evidenceType != "" && item.Type != evidenceType) {
			continue
		}
		result = append(result, evidenceToContext(item))
	}
	return result, nil
}

func (r ledgerEvidenceReader) ListLifecycleEvents(ctx context.Context, tenantID, evidenceID string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]evidencedomain.EvidenceLifecycleEvent, 0)
	for _, event := range r.ledger.lifecycle {
		if event.TenantID != tenantID || event.EvidenceID != evidenceID {
			continue
		}
		converted, err := lifecycleToEvidenceContext(event)
		if err != nil {
			return nil, err
		}
		result = append(result, converted)
	}
	return result, nil
}

type ledgerEvidenceTransactions struct{ ledger *Ledger }

func (r ledgerEvidenceTransactions) Execute(ctx context.Context, command evidenceapp.TransactionCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := r.ledger
	l.mu.Lock()
	tx := newLedgerEvidenceTransaction(l)
	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			tx.repositories = &repositories
			return command(ctx, tx)
		})
		if err != nil {
			l.mu.Unlock()
			return toEvidenceContextError(err)
		}
		tx.publish()
	} else {
		if err := command(ctx, tx); err != nil {
			l.mu.Unlock()
			return err
		}
		if err := tx.commitCompatibility(ctx); err != nil {
			l.mu.Unlock()
			return err
		}
	}
	localVEXJobs := append([]OutboxJob(nil), tx.localVEXJobs...)
	l.mu.Unlock()
	for _, job := range localVEXJobs {
		r.completeLocalVEXDecision(ctx, job.SubjectID)
	}
	return nil
}

type ledgerEvidenceTransaction struct {
	ledger        *Ledger
	repositories  *Repositories
	evidence      map[string]domain.EvidenceItem
	lifecycle     map[string]domain.EvidenceLifecycleEvent
	securityScans map[string]domain.SecurityScan
	sboms         map[string]domain.SBOM
	scans         map[string]domain.VulnerabilityScan
	contracts     map[string]domain.OpenAPIContract
	vexDocuments  map[string]domain.VEXDocument
	vexReports    map[string]domain.VEXImportReport
	decisions     map[string]domain.VulnerabilityDecision
	manualDocs    map[string]domain.ManualSecurityDocument
	sbomDiffs     map[string]domain.SBOMDiff
	contractDiffs map[string]domain.ContractDiff
	audit         []domain.AuditChainEntry
	outbox        []OutboxJob
	localVEXJobs  []OutboxJob
}

func newLedgerEvidenceTransaction(ledger *Ledger) *ledgerEvidenceTransaction {
	return &ledgerEvidenceTransaction{
		ledger: ledger, evidence: map[string]domain.EvidenceItem{}, lifecycle: map[string]domain.EvidenceLifecycleEvent{},
		sboms: map[string]domain.SBOM{}, scans: map[string]domain.VulnerabilityScan{}, contracts: map[string]domain.OpenAPIContract{},
		vexDocuments: map[string]domain.VEXDocument{}, vexReports: map[string]domain.VEXImportReport{},
		decisions:     map[string]domain.VulnerabilityDecision{},
		securityScans: map[string]domain.SecurityScan{}, manualDocs: map[string]domain.ManualSecurityDocument{},
		sbomDiffs: map[string]domain.SBOMDiff{}, contractDiffs: map[string]domain.ContractDiff{},
	}
}

func (t *ledgerEvidenceTransaction) Evidence() evidenceapp.Repository { return t }

func (t *ledgerEvidenceTransaction) Authorize(ctx context.Context, actor domain.Actor, request application.AuthorizationRequest) error {
	return (ledgerLockedContextAuthorizer{ledger: t.ledger}).Authorize(ctx, actor, request)
}
func (t *ledgerEvidenceTransaction) Ingestion() evidenceapp.IngestionRepository { return t }
func (t *ledgerEvidenceTransaction) Payloads() evidenceapp.PayloadRecorder      { return t }
func (t *ledgerEvidenceTransaction) Outbox() application.OutboxEnqueuer         { return t }
func (t *ledgerEvidenceTransaction) Audit() application.AuditAppender           { return t }

func (t *ledgerEvidenceTransaction) ValidateScope(ctx context.Context, tenantID string, scope evidenceapp.EvidenceScope) error {
	if err := validateLedgerEvidenceScopeLocked(t.ledger, tenantID, scope); err != nil {
		return toEvidenceContextError(err)
	}
	if t.repositories != nil {
		deploymentID := scope.DeploymentID
		if scope.AllowPendingDeployment {
			if _, exists := t.ledger.deployments[deploymentID]; !exists {
				deploymentID = ""
			}
		}
		if err := t.repositories.Evidence.ValidateEvidenceScope(ctx, tenantID, scope.ProductID, scope.ProjectID, scope.ReleaseID, scope.BuildID, deploymentID); err != nil {
			return toEvidenceContextError(err)
		}
	}
	return nil
}

func (t *ledgerEvidenceTransaction) ValidateLinkTarget(_ context.Context, tenantID, targetType, targetID string) error {
	return validateEvidenceLinkTarget(t.ledger, tenantID, targetType, targetID)
}

func (t *ledgerEvidenceTransaction) ValidateArtifactReference(ctx context.Context, tenantID, artifactID, digest string) error {
	artifactID = strings.TrimSpace(artifactID)
	if artifactID == "" {
		return nil
	}
	artifact, ok := t.ledger.artifacts[artifactID]
	if !ok || artifact.TenantID != tenantID || (digest != "" && !strings.EqualFold(artifact.Digest, digest)) {
		return evidenceapp.ErrNotFound
	}
	if t.repositories != nil {
		current, err := t.repositories.ReleaseCatalog.GetArtifact(ctx, tenantID, artifactID)
		if err != nil {
			return toEvidenceContextError(err)
		}
		if current.ID != artifact.ID || current.TenantID != artifact.TenantID || current.Name != artifact.Name || current.MediaType != artifact.MediaType || current.Size != artifact.Size || current.Digest != artifact.Digest {
			return evidenceapp.ErrConflict
		}
	}
	return nil
}

func validateEvidenceLinkTarget(ledger *Ledger, tenantID, targetType, targetID string) error {
	switch targetType {
	case "release":
		value, ok := ledger.releases[targetID]
		if !ok || value.TenantID != tenantID {
			return evidenceapp.ErrNotFound
		}
	case "product":
		value, ok := ledger.products[targetID]
		if !ok || value.TenantID != tenantID {
			return evidenceapp.ErrNotFound
		}
	default:
		return evidenceapp.ErrValidation
	}
	return nil
}

func (t *ledgerEvidenceTransaction) GetEvidence(ctx context.Context, tenantID, id string) (evidencedomain.EvidenceItem, error) {
	id = strings.TrimSpace(id)
	if t.repositories != nil {
		item, err := t.repositories.Evidence.GetEvidence(ctx, tenantID, id)
		if err != nil {
			return evidencedomain.EvidenceItem{}, toEvidenceContextError(err)
		}
		return evidenceToContext(item), nil
	}
	item, ok := t.evidence[id]
	if !ok {
		item, ok = t.ledger.evidence[id]
	}
	if !ok || item.TenantID != tenantID {
		return evidencedomain.EvidenceItem{}, evidenceapp.ErrNotFound
	}
	return evidenceToContext(item), nil
}

func (t *ledgerEvidenceTransaction) GetSBOM(ctx context.Context, tenantID, id string) (evidencedomain.SBOM, error) {
	id = strings.TrimSpace(id)
	if t.repositories != nil {
		value, err := t.repositories.Evidence.GetSBOM(ctx, tenantID, id)
		if err != nil {
			return evidencedomain.SBOM{}, toEvidenceContextError(err)
		}
		return sbomToEvidenceContext(value), nil
	}
	value, ok := t.ledger.sboms[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.SBOM{}, evidenceapp.ErrNotFound
	}
	return sbomToEvidenceContext(value), nil
}

func (t *ledgerEvidenceTransaction) GetOpenAPIContract(ctx context.Context, tenantID, id string) (evidencedomain.OpenAPIContract, error) {
	id = strings.TrimSpace(id)
	if t.repositories != nil {
		value, err := t.repositories.Evidence.GetOpenAPIContract(ctx, tenantID, id)
		if err != nil {
			return evidencedomain.OpenAPIContract{}, toEvidenceContextError(err)
		}
		return openAPIContractToEvidenceContext(value), nil
	}
	value, ok := t.ledger.contracts[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.OpenAPIContract{}, evidenceapp.ErrNotFound
	}
	return openAPIContractToEvidenceContext(value), nil
}

func (t *ledgerEvidenceTransaction) InsertEvidence(ctx context.Context, item evidencedomain.EvidenceItem) error {
	legacy := evidenceFromContext(item)
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertEvidence(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.evidence[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) RecordSupersession(ctx context.Context, item, replacement evidencedomain.EvidenceItem) error {
	legacyItem := evidenceFromContext(item)
	legacyReplacement := evidenceFromContext(replacement)
	if t.repositories != nil {
		if err := t.repositories.Evidence.RecordSupersession(ctx, legacyItem, legacyReplacement); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.evidence[legacyItem.ID] = legacyItem
	t.evidence[legacyReplacement.ID] = legacyReplacement
	return nil
}

func (t *ledgerEvidenceTransaction) CompareAndSwapEvidenceLinks(ctx context.Context, expected, replacement evidencedomain.EvidenceItem) error {
	legacyExpected := evidenceFromContext(expected)
	legacyReplacement := evidenceFromContext(replacement)
	if t.repositories != nil {
		if err := t.repositories.Evidence.CompareAndSwapEvidenceLinks(ctx, legacyExpected, legacyReplacement); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.evidence[legacyReplacement.ID] = legacyReplacement
	return nil
}

func (t *ledgerEvidenceTransaction) AppendLifecycle(ctx context.Context, event evidencedomain.EvidenceLifecycleEvent) error {
	legacy := lifecycleFromEvidenceContext(event)
	if t.repositories != nil {
		if err := t.repositories.Evidence.AppendLifecycle(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.lifecycle[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertSBOM(ctx context.Context, value evidencedomain.SBOM) error {
	legacy := sbomFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertSBOM(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.sboms[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertVulnerabilityScan(ctx context.Context, value evidencedomain.VulnerabilityScan) error {
	legacy := vulnerabilityScanFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertVulnerabilityScan(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.scans[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertOpenAPIContract(ctx context.Context, value evidencedomain.OpenAPIContract) error {
	legacy := openAPIContractFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertOpenAPIContract(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.contracts[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertVEXDocument(ctx context.Context, value evidencedomain.VEXDocument) error {
	legacy := vexDocumentFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertVEXDocument(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.vexDocuments[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertVEXImportReport(ctx context.Context, value evidencedomain.VEXImportReport) error {
	legacy := vexImportReportFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertVEXImportReport(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.vexReports[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertSecurityScan(ctx context.Context, value evidencedomain.SecurityScan) error {
	legacy := securityScanFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Risk.InsertSecurityScan(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.securityScans[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertManualSecurityDocument(ctx context.Context, value evidencedomain.ManualSecurityDocument) error {
	legacy := manualSecurityDocumentFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Risk.InsertManualSecurityDocument(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.manualDocs[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertSBOMDiff(ctx context.Context, value evidencedomain.SBOMDiff) error {
	legacy := sbomDiffFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Risk.InsertSBOMDiff(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.sbomDiffs[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) InsertContractDiff(ctx context.Context, value evidencedomain.ContractDiff) error {
	legacy := contractDiffFromEvidenceContext(value)
	if t.repositories != nil {
		if err := t.repositories.Risk.InsertContractDiff(ctx, legacy); err != nil {
			return toEvidenceContextError(err)
		}
	}
	t.contractDiffs[legacy.ID] = legacy
	return nil
}

func (t *ledgerEvidenceTransaction) RecordStagedPayload(ctx context.Context, payload evidenceapp.StagedPayload) error {
	if t.repositories == nil {
		return evidenceapp.ErrValidation
	}
	legacy := objectPayloadFromEvidenceContext(payload)
	if err := t.repositories.Payloads.RecordStagedObjectPayload(ctx, legacy); err != nil {
		return toEvidenceContextError(err)
	}
	return nil
}

func (t *ledgerEvidenceTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	job := OutboxJob{ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType, SubjectID: event.SubjectID, Payload: cloneMap(event.Payload), CreatedAt: event.CreatedAt}
	if err := EnsureOutboxDeduplicationKey(&job); err != nil {
		return evidenceapp.ErrValidation
	}
	if t.repositories != nil {
		if err := t.repositories.Outbox.Enqueue(ctx, job); err != nil {
			return toEvidenceContextError(err)
		}
		return nil
	}
	if event.Kind == "parse_vex" {
		if _, discardsJobs := t.ledger.outbox.(nopOutbox); discardsJobs {
			if t.repositories == nil && t.ledger.unitOfWork == nil && t.ledger.store == nil && !t.ledger.workerOwnedParsers {
				t.localVEXJobs = append(t.localVEXJobs, job)
				return nil
			}
			if _, persistsAtomically := t.ledger.store.(ReleaseLedgerMutationStore); !persistsAtomically {
				return evidenceapp.ErrValidation
			}
		}
	}
	t.outbox = append(t.outbox, job)
	return nil
}

func (t *ledgerEvidenceTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry := domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if t.repositories != nil {
		committed, err := t.repositories.Audit.Append(ctx, entry)
		if err != nil {
			return application.AuditReceipt{}, toEvidenceContextError(err)
		}
		entry = committed
	} else if err := t.completeCompatibilityAudit(&entry); err != nil {
		return application.AuditReceipt{}, toEvidenceContextError(err)
	}
	t.audit = append(t.audit, entry)
	return application.AuditReceipt{ID: entry.ID}, nil
}

func (t *ledgerEvidenceTransaction) completeCompatibilityAudit(entry *domain.AuditChainEntry) error {
	entries := t.ledger.chain[entry.TenantID]
	for _, pending := range t.audit {
		if pending.TenantID == entry.TenantID {
			entries = append(entries, pending)
		}
	}
	entry.Sequence = int64(len(entries) + 1)
	if len(entries) > 0 {
		entry.PreviousEntryHash = entries[len(entries)-1].EntryHash
	}
	return RehashAuditChainEntry(entry)
}

func (t *ledgerEvidenceTransaction) publish() {
	for id, item := range t.evidence {
		t.ledger.evidence[id] = item
	}
	for id, event := range t.lifecycle {
		t.ledger.lifecycle[id] = event
	}
	for id, sbom := range t.sboms {
		t.ledger.sboms[id] = sbom
	}
	for id, scan := range t.scans {
		t.ledger.scans[id] = scan
	}
	for id, contract := range t.contracts {
		t.ledger.contracts[id] = contract
	}
	for id, document := range t.vexDocuments {
		t.ledger.vexDocuments[id] = document
	}
	for id, report := range t.vexReports {
		t.ledger.vexImportReports[id] = report
	}
	for id, decision := range t.decisions {
		t.ledger.decisions[id] = decision
	}
	for id, scan := range t.securityScans {
		t.ledger.securityScans[id] = scan
	}
	for id, document := range t.manualDocs {
		t.ledger.manualDocs[id] = document
	}
	for id, diff := range t.sbomDiffs {
		t.ledger.sbomDiffs[id] = diff
		for _, change := range diff.DependencyChanges {
			t.ledger.depChanges[change.ID] = change
		}
	}
	for id, diff := range t.contractDiffs {
		t.ledger.contractDiffs[id] = diff
	}
	for _, entry := range t.audit {
		t.ledger.publishCommittedAuditEntryLocked(entry)
	}
	for _, job := range t.localVEXJobs {
		t.ledger.localVEXJobs[job.SubjectID] = job
	}
}

func (t *ledgerEvidenceTransaction) commitCompatibility(ctx context.Context) error {
	evidence := cloneEvidenceMap(t.ledger.evidence)
	lifecycle := cloneEvidenceLifecycleMap(t.ledger.lifecycle)
	sboms := cloneSBOMMap(t.ledger.sboms)
	scans := cloneVulnerabilityScanMap(t.ledger.scans)
	contracts := cloneOpenAPIContractMap(t.ledger.contracts)
	vexDocuments := cloneVEXDocumentMap(t.ledger.vexDocuments)
	vexReports := cloneVEXImportReportMap(t.ledger.vexImportReports)
	decisions := cloneVulnerabilityDecisionMap(t.ledger.decisions)
	securityScans := cloneSecurityScanMap(t.ledger.securityScans)
	manualDocs := cloneManualSecurityDocumentMap(t.ledger.manualDocs)
	sbomDiffs := cloneSBOMDiffMap(t.ledger.sbomDiffs)
	dependencyChanges := cloneDependencyChangeMap(t.ledger.depChanges)
	contractDiffs := cloneContractDiffMap(t.ledger.contractDiffs)
	chain := cloneAuditChainMap(t.ledger.chain)
	localVEXJobs := cloneOutboxJobMap(t.ledger.localVEXJobs)
	t.publish()
	persist := func(ctx context.Context) error {
		mutation, err := t.ledger.releaseLedgerMutationLocked()
		if err != nil {
			return err
		}
		mutation.OutboxJobs = append(mutation.OutboxJobs, t.outbox...)
		if _, ok := t.ledger.store.(ReleaseLedgerMutationStore); !ok {
			for _, job := range t.outbox {
				if err := t.ledger.enqueueJob(ctx, job); err != nil {
					return err
				}
			}
		}
		return t.ledger.persistReleaseLedgerLocked(ctx, mutation)
	}
	if len(t.securityScans) > 0 || len(t.manualDocs) > 0 || len(t.sbomDiffs) > 0 || len(t.contractDiffs) > 0 {
		persist = func(ctx context.Context) error {
			if len(t.outbox) > 0 {
				return evidenceapp.ErrValidation
			}
			return t.ledger.persistLocked(ctx)
		}
	}
	if err := persist(ctx); err != nil {
		t.ledger.evidence = evidence
		t.ledger.lifecycle = lifecycle
		t.ledger.sboms = sboms
		t.ledger.scans = scans
		t.ledger.contracts = contracts
		t.ledger.vexDocuments = vexDocuments
		t.ledger.vexImportReports = vexReports
		t.ledger.decisions = decisions
		t.ledger.securityScans = securityScans
		t.ledger.manualDocs = manualDocs
		t.ledger.sbomDiffs = sbomDiffs
		t.ledger.depChanges = dependencyChanges
		t.ledger.contractDiffs = contractDiffs
		t.ledger.chain = chain
		t.ledger.localVEXJobs = localVEXJobs
		return toEvidenceContextError(err)
	}
	return nil
}

func cloneOutboxJobMap(values map[string]OutboxJob) map[string]OutboxJob {
	result := make(map[string]OutboxJob, len(values))
	for id, job := range values {
		job.Payload = cloneMap(job.Payload)
		result[id] = job
	}
	return result
}

func evidenceToContext(value domain.EvidenceItem) evidencedomain.EvidenceItem {
	return domain.EvidenceToContextModel(value)
}

func evidenceFromContext(value evidencedomain.EvidenceItem) domain.EvidenceItem {
	return domain.EvidenceFromContextModel(value)
}

func sbomToEvidenceContext(value domain.SBOM) evidencedomain.SBOM {
	var components []evidencedomain.SBOMComponent
	if value.Components != nil {
		components = make([]evidencedomain.SBOMComponent, 0, len(value.Components))
	}
	for _, component := range value.Components {
		components = append(components, sbomComponentToEvidenceContext(component))
	}
	return evidencedomain.SBOM{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID,
		ArtifactID: value.ArtifactID, Format: value.Format, SpecVersion: value.SpecVersion,
		ComponentCount: value.ComponentCount, Components: components, CreatedAt: value.CreatedAt,
	}
}

func sbomFromEvidenceContext(value evidencedomain.SBOM) domain.SBOM {
	return domain.SBOMFromContext(value)
}

func sbomComponentToEvidenceContext(value domain.SBOMComponent) evidencedomain.SBOMComponent {
	return evidencedomain.SBOMComponent{Identity: value.Identity, Name: value.Name, Version: value.Version, PURL: value.PURL}
}

func openAPIContractToEvidenceContext(value domain.OpenAPIContract) evidencedomain.OpenAPIContract {
	var operations []evidencedomain.OpenAPIOperation
	if value.Operations != nil {
		operations = make([]evidencedomain.OpenAPIOperation, 0, len(value.Operations))
	}
	for _, operation := range value.Operations {
		operations = append(operations, evidencedomain.OpenAPIOperation{
			Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID, Deprecated: operation.Deprecated,
			RequestBodyRequired:   operation.RequestBodyRequired,
			RequiredRequestFields: append([]string(nil), operation.RequiredRequestFields...),
			ResponseStatuses:      append([]string(nil), operation.ResponseStatuses...),
		})
	}
	return evidencedomain.OpenAPIContract{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID,
		Version: value.Version, Hash: value.Hash, PathCount: value.PathCount, Operations: operations,
		EvidenceID: value.EvidenceID, CreatedAt: value.CreatedAt,
	}
}

func openAPIContractFromEvidenceContext(value evidencedomain.OpenAPIContract) domain.OpenAPIContract {
	return domain.OpenAPIContractFromContext(value)
}

func vexDocumentToEvidenceContext(value domain.VEXDocument) evidencedomain.VEXDocument {
	return evidencedomain.VEXDocument{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID,
		ArtifactID: value.ArtifactID, Format: value.Format, Author: value.Author, Version: value.Version,
		StatementCount: value.StatementCount, StatusSummary: cloneNullableIntMap(value.StatusSummary),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func vexDocumentFromEvidenceContext(value evidencedomain.VEXDocument) domain.VEXDocument {
	return domain.VEXDocumentFromContext(value)
}

func vexImportReportToEvidenceContext(value domain.VEXImportReport) evidencedomain.VEXImportReport {
	return evidencedomain.VEXImportReport{
		ID: value.ID, TenantID: value.TenantID, VEXDocumentID: value.VEXDocumentID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, ParserVersion: value.ParserVersion, Status: value.Status,
		StatementCount: value.StatementCount, DecisionsCreated: value.DecisionsCreated, DecisionsSuperseded: value.DecisionsSuperseded,
		UnsupportedFields: append([]string(nil), value.UnsupportedFields...), Warnings: append([]string(nil), value.Warnings...),
		InvalidStatements: vexImportIssuesToEvidenceContext(value.InvalidStatements), MappingFailures: vexImportIssuesToEvidenceContext(value.MappingFailures),
		FailureCode: value.FailureCode, FailureDetail: value.FailureDetail, SchemaVersion: value.SchemaVersion,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func vexImportReportFromEvidenceContext(value evidencedomain.VEXImportReport) domain.VEXImportReport {
	return domain.VEXImportReportFromContext(value)
}

func vexImportIssuesToEvidenceContext(values []domain.VEXImportIssue) []evidencedomain.VEXImportIssue {
	result := make([]evidencedomain.VEXImportIssue, 0, len(values))
	for _, value := range values {
		result = append(result, evidencedomain.VEXImportIssue{StatementIndex: value.StatementIndex, Code: value.Code, Detail: value.Detail})
	}
	return result
}

func vulnerabilityScanFromEvidenceContext(value evidencedomain.VulnerabilityScan) domain.VulnerabilityScan {
	return domain.VulnerabilityScanFromContext(value)
}

func vulnerabilityScanToEvidenceContext(value domain.VulnerabilityScan) evidencedomain.VulnerabilityScan {
	var findings []evidencedomain.VulnerabilityFinding
	if value.Findings != nil {
		findings = make([]evidencedomain.VulnerabilityFinding, 0, len(value.Findings))
	}
	for _, finding := range value.Findings {
		findings = append(findings, evidencedomain.VulnerabilityFinding{
			ID: finding.ID, Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity,
			State: finding.State, SeveritySource: finding.SeveritySource, FixVersion: finding.FixVersion,
			Identity: evidencedomain.VulnerabilityIdentity{
				CVE: finding.Identity.CVE, GHSA: finding.Identity.GHSA, OSV: finding.Identity.OSV,
				VendorAdvisory: finding.Identity.VendorAdvisory, PURL: finding.Identity.PURL, CPE: finding.Identity.CPE,
			},
		})
	}
	return evidencedomain.VulnerabilityScan{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID,
		Scanner: value.Scanner, Adapter: value.Adapter, AdapterVersion: value.AdapterVersion,
		SourceSchema: value.SourceSchema, TargetRef: value.TargetRef, Summary: cloneNullableIntMap(value.Summary),
		Findings: findings, CreatedAt: value.CreatedAt,
	}
}

func cloneNullableIntMap(values map[string]int) map[string]int {
	if values == nil {
		return nil
	}
	result := make(map[string]int, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func securityScanFromEvidenceContext(value evidencedomain.SecurityScan) domain.SecurityScan {
	return domain.SecurityScanFromContext(value)
}

func manualSecurityDocumentFromEvidenceContext(value evidencedomain.ManualSecurityDocument) domain.ManualSecurityDocument {
	return domain.ManualSecurityDocumentFromContext(value)
}

func sbomDiffFromEvidenceContext(value evidencedomain.SBOMDiff) domain.SBOMDiff {
	return domain.SBOMDiffFromContext(value)
}

func contractDiffFromEvidenceContext(value evidencedomain.ContractDiff) domain.ContractDiff {
	return domain.ContractDiffFromContext(value)
}

func lifecycleToEvidenceContext(value domain.EvidenceLifecycleEvent) (evidencedomain.EvidenceLifecycleEvent, error) {
	action, err := evidencedomain.ParseEvidenceLifecycleState(value.Action)
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, evidenceapp.ErrValidation
	}
	return evidencedomain.EvidenceLifecycleEvent{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, Action: action,
		Reason: value.Reason, Details: cloneMap(value.Details), ReplacementID: value.ReplacementID,
		ActorID: value.ActorID, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}, nil
}

func lifecycleFromEvidenceContext(value evidencedomain.EvidenceLifecycleEvent) domain.EvidenceLifecycleEvent {
	return domain.EvidenceLifecycleEvent{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, Action: value.Action.String(),
		Reason: value.Reason, Details: cloneMap(value.Details), ReplacementID: value.ReplacementID,
		ActorID: value.ActorID, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func objectPayloadToEvidenceContext(value ObjectPayload) evidenceapp.StagedPayload {
	return evidenceapp.StagedPayload{
		TenantID: value.TenantID, Digest: value.Digest, Size: value.Size, MediaType: value.MediaType, StagingKey: value.StagingKey,
		FinalKey: value.FinalKey, Status: string(value.Status), FailureCode: value.FailureCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		FinalizedAt: value.FinalizedAt, FailedAt: value.FailedAt, OrphanedAt: value.OrphanedAt,
	}
}

func objectPayloadFromEvidenceContext(value evidenceapp.StagedPayload) ObjectPayload {
	return ObjectPayload{
		TenantID: value.TenantID, Digest: value.Digest, Size: value.Size, MediaType: value.MediaType, StagingKey: value.StagingKey,
		FinalKey: value.FinalKey, Status: ObjectPayloadStatus(value.Status), FailureCode: value.FailureCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		FinalizedAt: value.FinalizedAt, FailedAt: value.FailedAt, OrphanedAt: value.OrphanedAt,
	}
}

func toEvidenceContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrValidation):
		return evidenceapp.ErrValidation
	case errors.Is(err, ErrForbidden):
		return evidenceapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return evidenceapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return evidenceapp.ErrConflict
	default:
		return err
	}
}

func fromEvidenceContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, evidenceapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, evidenceapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, evidenceapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, evidenceapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}

func cloneEvidenceMap(values map[string]domain.EvidenceItem) map[string]domain.EvidenceItem {
	result := make(map[string]domain.EvidenceItem, len(values))
	for key, value := range values {
		result[key] = evidenceFromContext(evidenceToContext(value))
	}
	return result
}

func cloneSBOMMap(values map[string]domain.SBOM) map[string]domain.SBOM {
	result := make(map[string]domain.SBOM, len(values))
	for key, value := range values {
		result[key] = sbomFromEvidenceContext(sbomToEvidenceContext(value))
	}
	return result
}

func cloneVulnerabilityScanMap(values map[string]domain.VulnerabilityScan) map[string]domain.VulnerabilityScan {
	result := make(map[string]domain.VulnerabilityScan, len(values))
	for key, value := range values {
		result[key] = vulnerabilityScanFromEvidenceContext(vulnerabilityScanToEvidenceContext(value))
	}
	return result
}

func cloneVEXDocumentMap(values map[string]domain.VEXDocument) map[string]domain.VEXDocument {
	result := make(map[string]domain.VEXDocument, len(values))
	for key, value := range values {
		result[key] = vexDocumentFromEvidenceContext(vexDocumentToEvidenceContext(value))
	}
	return result
}

func cloneVEXImportReportMap(values map[string]domain.VEXImportReport) map[string]domain.VEXImportReport {
	result := make(map[string]domain.VEXImportReport, len(values))
	for key, value := range values {
		result[key] = vexImportReportFromEvidenceContext(vexImportReportToEvidenceContext(value))
	}
	return result
}

func cloneOpenAPIContractMap(values map[string]domain.OpenAPIContract) map[string]domain.OpenAPIContract {
	result := make(map[string]domain.OpenAPIContract, len(values))
	for key, value := range values {
		result[key] = openAPIContractFromEvidenceContext(openAPIContractToEvidenceContext(value))
	}
	return result
}

func cloneEvidenceLifecycleMap(values map[string]domain.EvidenceLifecycleEvent) map[string]domain.EvidenceLifecycleEvent {
	result := make(map[string]domain.EvidenceLifecycleEvent, len(values))
	for key, value := range values {
		value.Details = cloneMap(value.Details)
		result[key] = value
	}
	return result
}

func cloneSecurityScanMap(values map[string]domain.SecurityScan) map[string]domain.SecurityScan {
	result := make(map[string]domain.SecurityScan, len(values))
	for key, value := range values {
		value.Summary = cloneIntMap(value.Summary)
		result[key] = value
	}
	return result
}

func cloneManualSecurityDocumentMap(values map[string]domain.ManualSecurityDocument) map[string]domain.ManualSecurityDocument {
	result := make(map[string]domain.ManualSecurityDocument, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneSBOMDiffMap(values map[string]domain.SBOMDiff) map[string]domain.SBOMDiff {
	result := make(map[string]domain.SBOMDiff, len(values))
	for key, value := range values {
		value.AddedComponents = append([]domain.SBOMComponent(nil), value.AddedComponents...)
		value.RemovedComponents = append([]domain.SBOMComponent(nil), value.RemovedComponents...)
		value.DependencyChanges = append([]domain.DependencyChange(nil), value.DependencyChanges...)
		result[key] = value
	}
	return result
}

func cloneDependencyChangeMap(values map[string]domain.DependencyChange) map[string]domain.DependencyChange {
	result := make(map[string]domain.DependencyChange, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneContractDiffMap(values map[string]domain.ContractDiff) map[string]domain.ContractDiff {
	result := make(map[string]domain.ContractDiff, len(values))
	for key, value := range values {
		value.BreakingChanges = append([]string(nil), value.BreakingChanges...)
		value.NonBreakingChanges = append([]string(nil), value.NonBreakingChanges...)
		result[key] = value
	}
	return result
}
