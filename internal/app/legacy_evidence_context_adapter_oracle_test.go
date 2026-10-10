package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Only historical tests compose the aggregate Evidence adapter.
func (l *Ledger) legacyEvidenceCommands() *evidenceapp.Service {
	parser := ledgerEvidencePayloadParser{}
	service, err := evidenceapp.NewService(evidenceapp.Config{
		Reader: ledgerEvidenceReader{ledger: l}, Transactions: ledgerEvidenceTransactions{ledger: l},
		ProjectionRefresher: ledgerEvidenceProjectionRefresher{ledger: l},
		Authorizer:          ledgerContextAuthorizer{ledger: l}, Objects: ledgerEvidenceObjectIngestion{ledger: l},
		SourceObjects: ledgerEvidenceSourceObjectIngestion{ledger: l}, Parser: parser, VulnerabilityScanScopeProber: parser,
		Canonicalizer: evidenceCanonicalHasher{}, LifecycleSanitizer: ledgerEvidenceLifecycleSanitizer{}, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion,
		Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID),
		WorkerOwnedParsers: l.workerOwnedParsers,
	})
	if err != nil {
		panic(err)
	}
	return service
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
