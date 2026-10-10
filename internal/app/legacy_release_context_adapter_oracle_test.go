package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// Only historical characterization composes the aggregate Release adapter.
func (l *Ledger) legacyReleaseCommands() *releaseapp.Service {
	service, err := releaseapp.NewService(releaseapp.Config{
		Reader:              ledgerReleaseReader{ledger: l},
		Transactions:        ledgerReleaseTransactions{ledger: l},
		Authorizer:          ledgerContextAuthorizer{ledger: l},
		CandidateReferences: ledgerReleaseCandidateReferences{ledger: l},
		Canonicalizer:       ledgerReleaseCandidateCanonicalizer{},
		AttestationParser:   l.buildAttestationParser,
		PayloadStager:       ledgerBuildAttestationPayloadStager{ledger: l},
		WorkerOwnedParsers:  l.workerOwnedParsers,
		Clock:               application.ClockFunc(l.now),
		IDs:                 application.IDGeneratorFunc(newID),
	})
	if err != nil {
		panic(err)
	}
	return service
}

type ledgerBuildAttestationPayloadStager struct{ ledger *Ledger }

func (s ledgerBuildAttestationPayloadStager) StageBuildAttestationPayload(ctx context.Context, tenantID string, source releaseapp.BuildAttestationPayloadSource) (releaseapp.StagedBuildAttestationPayload, error) {
	payload, err := s.ledger.stagePayloadSource(ctx, tenantID, releaseapp.BuildAttestationMediaType, PayloadSource{
		Digest: source.Digest, Size: source.Size, Open: source.Open,
	})
	if err != nil {
		return releaseapp.StagedBuildAttestationPayload{}, toReleaseContextError(err)
	}
	return stagedBuildAttestationPayloadToReleaseContext(payload), nil
}

type ledgerReleaseCandidateReferences struct{ ledger *Ledger }

func (v ledgerReleaseCandidateReferences) ValidateReleaseCandidateReferences(ctx context.Context, tenantID, releaseID string, refs releaseapp.ReleaseCandidateReferences) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.ledger.mu.Lock()
	defer v.ledger.mu.Unlock()
	return toReleaseContextError(v.ledger.validateCandidateRefsLocked(tenantID, releaseID, CreateReleaseCandidateInput{
		BuildIDs: refs.BuildIDs, ArtifactIDs: refs.ArtifactIDs, SBOMIDs: refs.SBOMIDs,
		ScanIDs: refs.ScanIDs, VEXIDs: refs.VEXIDs, ContractIDs: refs.ContractIDs, BundleIDs: refs.BundleIDs,
	}))
}

type ledgerReleaseCandidateCanonicalizer struct{}

func (ledgerReleaseCandidateCanonicalizer) HashReleaseCandidate(_ context.Context, candidate releasedomain.ReleaseCandidate) (string, error) {
	return canonicalAnyHash(releaseCandidateFromReleaseContext(candidate))
}

type ledgerReleaseReader struct{ ledger *Ledger }

func (r ledgerReleaseReader) ListProducts(ctx context.Context, tenantID string) ([]releasedomain.Product, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]releasedomain.Product, 0)
	for _, product := range r.ledger.products {
		if product.TenantID == tenantID {
			result = append(result, productToReleaseContext(product))
		}
	}
	return result, nil
}

func (r ledgerReleaseReader) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	if err := ctx.Err(); err != nil {
		return releasedomain.Product{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	product, ok := r.ledger.products[strings.TrimSpace(id)]
	if !ok || product.TenantID != tenantID {
		return releasedomain.Product{}, releaseapp.ErrNotFound
	}
	return productToReleaseContext(product), nil
}

func (r ledgerReleaseReader) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	if err := ctx.Err(); err != nil {
		return releasedomain.Project{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	project, ok := r.ledger.projects[strings.TrimSpace(id)]
	if !ok || project.TenantID != tenantID {
		return releasedomain.Project{}, releaseapp.ErrNotFound
	}
	return projectToReleaseContext(project), nil
}

func (r ledgerReleaseReader) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	if err := ctx.Err(); err != nil {
		return releasedomain.Release{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	release, ok := r.ledger.releases[strings.TrimSpace(id)]
	if !ok || release.TenantID != tenantID {
		return releasedomain.Release{}, releaseapp.ErrNotFound
	}
	return legacyReleaseToContext(release)
}

func (r ledgerReleaseReader) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	if err := ctx.Err(); err != nil {
		return releasedomain.Artifact{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	artifact, ok := r.ledger.artifacts[strings.TrimSpace(id)]
	if !ok || artifact.TenantID != tenantID {
		return releasedomain.Artifact{}, releaseapp.ErrNotFound
	}
	return artifactToReleaseContext(artifact), nil
}

func (r ledgerReleaseReader) GetBuildRun(ctx context.Context, tenantID, id string) (releasedomain.BuildRun, error) {
	if err := ctx.Err(); err != nil {
		return releasedomain.BuildRun{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	build, ok := r.ledger.buildRuns[strings.TrimSpace(id)]
	if !ok || build.TenantID != tenantID {
		return releasedomain.BuildRun{}, releaseapp.ErrNotFound
	}
	return buildRunToReleaseContext(build), nil
}

func (r ledgerReleaseReader) GetReleaseCandidate(ctx context.Context, tenantID, id string) (releasedomain.ReleaseCandidate, error) {
	if err := ctx.Err(); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	candidate, ok := r.ledger.candidates[strings.TrimSpace(id)]
	if !ok || candidate.TenantID != tenantID {
		return releasedomain.ReleaseCandidate{}, releaseapp.ErrNotFound
	}
	return releaseCandidateToReleaseContext(candidate)
}

func (r ledgerReleaseReader) ListReleaseCandidates(ctx context.Context, tenantID, releaseID string) ([]releasedomain.ReleaseCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]releasedomain.ReleaseCandidate, 0)
	for _, candidate := range r.ledger.candidates {
		if candidate.TenantID != tenantID || (releaseID != "" && candidate.ReleaseID != releaseID) {
			continue
		}
		mapped, err := releaseCandidateToReleaseContext(candidate)
		if err != nil {
			return nil, err
		}
		result = append(result, mapped)
	}
	return result, nil
}

type ledgerReleaseTransactions struct{ ledger *Ledger }

func (r ledgerReleaseTransactions) Execute(ctx context.Context, command releaseapp.TransactionCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := r.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	tx := newLedgerReleaseTransaction(l)
	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			tx.repositories = &repositories
			return command(ctx, tx)
		})
		if err != nil {
			return toReleaseContextError(err)
		}
		tx.publish()
		return nil
	}
	if err := command(ctx, tx); err != nil {
		return err
	}
	return tx.commitCompatibility(ctx)
}

type ledgerReleaseTransaction struct {
	ledger       *Ledger
	repositories *Repositories
	products     map[string]domain.Product
	projects     map[string]domain.Project
	releases     map[string]domain.Release
	artifacts    map[string]domain.Artifact
	buildRuns    map[string]domain.BuildRun
	attestations map[string]domain.BuildAttestation
	evidence     map[string]domain.EvidenceItem
	candidates   map[string]domain.ReleaseCandidate
	images       map[string]domain.ContainerImage
	audit        []domain.AuditChainEntry
	outbox       []OutboxJob
}

func newLedgerReleaseTransaction(ledger *Ledger) *ledgerReleaseTransaction {
	return &ledgerReleaseTransaction{
		ledger: ledger, products: map[string]domain.Product{}, projects: map[string]domain.Project{},
		releases: map[string]domain.Release{}, artifacts: map[string]domain.Artifact{},
		buildRuns: map[string]domain.BuildRun{}, attestations: map[string]domain.BuildAttestation{},
		evidence: map[string]domain.EvidenceItem{}, candidates: map[string]domain.ReleaseCandidate{},
		images: map[string]domain.ContainerImage{},
	}
}

func (t *ledgerReleaseTransaction) Catalog() releaseapp.CatalogRepository { return t }
func (t *ledgerReleaseTransaction) Builds() releaseapp.BuildRepository    { return t }
func (t *ledgerReleaseTransaction) BuildAttestationEvidence() releaseapp.BuildAttestationEvidenceWriter {
	return t
}
func (t *ledgerReleaseTransaction) SupplyChain() releaseapp.SupplyChainRepository {
	return t
}
func (t *ledgerReleaseTransaction) Authorization() application.Authorizer {
	return ledgerLockedContextAuthorizer{ledger: t.ledger}
}
func (t *ledgerReleaseTransaction) Audit() application.AuditAppender   { return t }
func (t *ledgerReleaseTransaction) Outbox() application.OutboxEnqueuer { return t }

func (t *ledgerReleaseTransaction) ProductBySlug(_ context.Context, tenantID, slug string) (releasedomain.Product, bool, error) {
	for _, product := range t.products {
		if product.TenantID == tenantID && product.Slug == slug {
			return productToReleaseContext(product), true, nil
		}
	}
	for _, product := range t.ledger.products {
		if product.TenantID == tenantID && product.Slug == slug {
			return productToReleaseContext(product), true, nil
		}
	}
	return releasedomain.Product{}, false, nil
}

func (t *ledgerReleaseTransaction) GetProduct(_ context.Context, tenantID, id string) (releasedomain.Product, error) {
	product, ok := t.products[id]
	if !ok {
		product, ok = t.ledger.products[id]
	}
	if !ok || product.TenantID != tenantID {
		return releasedomain.Product{}, releaseapp.ErrNotFound
	}
	return productToReleaseContext(product), nil
}

func (t *ledgerReleaseTransaction) InsertProduct(ctx context.Context, product releasedomain.Product) error {
	legacy := productFromReleaseContext(product)
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.InsertProduct(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.products[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) GetProject(_ context.Context, tenantID, id string) (releasedomain.Project, error) {
	project, ok := t.projects[id]
	if !ok {
		project, ok = t.ledger.projects[id]
	}
	if !ok || project.TenantID != tenantID {
		return releasedomain.Project{}, releaseapp.ErrNotFound
	}
	return projectToReleaseContext(project), nil
}

func (t *ledgerReleaseTransaction) InsertProject(ctx context.Context, project releasedomain.Project) error {
	legacy := projectFromReleaseContext(project)
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.InsertProject(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.projects[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) ReleaseByVersion(_ context.Context, tenantID, productID, version string) (releasedomain.Release, bool, error) {
	for _, release := range t.releases {
		if release.TenantID == tenantID && release.ProductID == productID && release.Version == version {
			value, err := legacyReleaseToContext(release)
			return value, err == nil, err
		}
	}
	for _, release := range t.ledger.releases {
		if release.TenantID == tenantID && release.ProductID == productID && release.Version == version {
			value, err := legacyReleaseToContext(release)
			return value, err == nil, err
		}
	}
	return releasedomain.Release{}, false, nil
}

func (t *ledgerReleaseTransaction) GetRelease(_ context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, ok := t.releases[id]
	if !ok {
		release, ok = t.ledger.releases[id]
	}
	if !ok || release.TenantID != tenantID {
		return releasedomain.Release{}, releaseapp.ErrNotFound
	}
	return legacyReleaseToContext(release)
}

func (t *ledgerReleaseTransaction) InsertRelease(ctx context.Context, release releasedomain.Release) error {
	legacy := domain.ReleaseFromContextModel(release)
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.InsertRelease(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.releases[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) UpdateRelease(ctx context.Context, release releasedomain.Release, expectedRevision int64) error {
	current, ok := t.ledger.releases[release.ID]
	if pending, pendingOK := t.releases[release.ID]; pendingOK {
		current, ok = pending, true
	}
	if !ok || current.TenantID != release.TenantID {
		return releaseapp.ErrNotFound
	}
	if current.Revision != expectedRevision {
		return releaseapp.NewVersionConflict(current.Revision)
	}
	legacy := domain.ReleaseFromContextModel(release)
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.UpdateReleaseState(ctx, legacy, current.State); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.releases[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) ArtifactByDigest(_ context.Context, tenantID, digest string) (releasedomain.Artifact, bool, error) {
	for _, artifact := range t.artifacts {
		if artifact.TenantID == tenantID && artifact.Digest == digest {
			return artifactToReleaseContext(artifact), true, nil
		}
	}
	for _, artifact := range t.ledger.artifacts {
		if artifact.TenantID == tenantID && artifact.Digest == digest {
			return artifactToReleaseContext(artifact), true, nil
		}
	}
	return releasedomain.Artifact{}, false, nil
}

func (t *ledgerReleaseTransaction) GetArtifact(_ context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	artifact, ok := t.artifacts[id]
	if !ok {
		artifact, ok = t.ledger.artifacts[id]
	}
	if !ok || artifact.TenantID != tenantID {
		return releasedomain.Artifact{}, releaseapp.ErrNotFound
	}
	return artifactToReleaseContext(artifact), nil
}

func (t *ledgerReleaseTransaction) InsertArtifact(ctx context.Context, artifact releasedomain.Artifact) error {
	legacy := artifactFromReleaseContext(artifact)
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.InsertArtifact(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.artifacts[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) GetReleaseCandidate(_ context.Context, tenantID, id string) (releasedomain.ReleaseCandidate, error) {
	candidate, ok := t.candidates[id]
	if !ok {
		candidate, ok = t.ledger.candidates[id]
	}
	if !ok || candidate.TenantID != tenantID {
		return releasedomain.ReleaseCandidate{}, releaseapp.ErrNotFound
	}
	return releaseCandidateToReleaseContext(candidate)
}

func (t *ledgerReleaseTransaction) InsertReleaseCandidate(ctx context.Context, candidate releasedomain.ReleaseCandidate) error {
	legacy := releaseCandidateFromReleaseContext(candidate)
	if _, exists := t.ledger.candidates[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if _, exists := t.candidates[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.candidates[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) UpdateReleaseCandidateState(ctx context.Context, candidate releasedomain.ReleaseCandidate, expectedRevision int64, expectedState string) error {
	current, ok := t.candidates[candidate.ID]
	if !ok {
		current, ok = t.ledger.candidates[candidate.ID]
	}
	if !ok || current.TenantID != candidate.TenantID || current.ReleaseID != candidate.ReleaseID {
		return releaseapp.ErrNotFound
	}
	if current.Revision != expectedRevision {
		return releaseapp.NewVersionConflict(current.Revision)
	}
	if current.State != expectedState {
		return releaseapp.ErrConflict
	}
	legacy := releaseCandidateFromReleaseContext(candidate)
	if t.repositories != nil {
		if err := t.repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, legacy, expectedState); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.candidates[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) GetBuildRun(_ context.Context, tenantID, id string) (releasedomain.BuildRun, error) {
	build, ok := t.buildRuns[id]
	if !ok {
		build, ok = t.ledger.buildRuns[id]
	}
	if !ok || build.TenantID != tenantID {
		return releasedomain.BuildRun{}, releaseapp.ErrNotFound
	}
	return buildRunToReleaseContext(build), nil
}

func (t *ledgerReleaseTransaction) InsertBuildRun(ctx context.Context, build releasedomain.BuildRun) error {
	legacy := buildRunFromReleaseContext(build)
	if _, exists := t.ledger.buildRuns[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if _, exists := t.buildRuns[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Builds.InsertBuildRun(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.buildRuns[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) InsertBuildAttestation(ctx context.Context, attestation releasedomain.BuildAttestation) error {
	legacy := buildAttestationFromReleaseContext(attestation)
	if _, exists := t.ledger.attestations[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if _, exists := t.attestations[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Builds.InsertBuildAttestation(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.attestations[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) WriteBuildAttestationEvidence(ctx context.Context, actor identitydomain.Actor, input releaseapp.BuildAttestationEvidenceInput) (releaseapp.BuildAttestationEvidenceReceipt, error) {
	if err := ctx.Err(); err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, err
	}
	subjects := make([]domain.SubjectRef, 0, len(input.Subjects))
	for _, subject := range input.Subjects {
		subjects = append(subjects, domain.SubjectRef{Type: subject.Type, ID: subject.ID, Digest: subject.Digest})
	}
	staged := stagedBuildAttestationPayloadFromReleaseContext(input.StagedPayload)
	item, err := t.ledger.newEvidenceItemForScopeLocked(actor, ScopeBuildWrite, CreateEvidenceInput{
		ProductID: input.ProductID, ProjectID: input.ProjectID, ReleaseID: input.ReleaseID, BuildID: input.BuildID,
		Type: "build_attestation", Subtype: "dsse_in_toto", Title: "DSSE in-toto build attestation",
		SourceSystem: input.SourceSystem, SourceIdentity: cloneMap(input.SourceIdentity), CollectorID: input.CollectorID,
		ObservedAt: input.ObservedAt, PayloadRef: input.PayloadRef, PayloadHash: input.PayloadHash,
		PayloadMediaType: input.PayloadMediaType, PayloadSize: input.PayloadSize, StagedPayload: staged,
		SubjectRefs: subjects,
		Metadata: WithParserProvenance(map[string]any{
			"payload_type": input.PayloadType, "predicate_type": input.PredicateType, "signature_count": input.SignatureCount,
		}, ParserProvenance{
			Name: "dsse-in-toto", Version: input.ParserVersion, SourceSchema: "in-toto-statement.v1",
			NormalizedSchema: "evydence-build-attestation.v1", ReplayStatus: ParserReplayStatusOriginal,
		}),
		Limitations: []string{"Structural DSSE/in-toto parsing does not assign trust. A separately recorded offline verification receipt is required for release readiness."},
	})
	if err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, toReleaseContextError(err)
	}
	if t.repositories != nil {
		if err := t.repositories.Evidence.ValidateEvidenceScope(ctx, actor.TenantID, input.ProductID, input.ProjectID, input.ReleaseID, input.BuildID, ""); err != nil {
			return releaseapp.BuildAttestationEvidenceReceipt{}, toReleaseContextError(err)
		}
		if err := t.ledger.persistStagedObjectPayload(ctx, *t.repositories, staged); err != nil {
			return releaseapp.BuildAttestationEvidenceReceipt{}, toReleaseContextError(err)
		}
	}
	audit, err := t.AppendAudit(ctx, application.AuditEvent{
		ID: newID("ace"), TenantID: actor.TenantID, EntryType: "evidence.created", SubjectType: "evidence_item",
		SubjectID: item.ID, ActorType: actorType(actor), ActorID: actorID(actor), OccurredAt: item.CreatedAt,
		PayloadHash: item.PayloadHash,
	})
	if err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, err
	}
	item.ChainEntryID = audit.ID
	if t.repositories != nil {
		if err := t.repositories.Evidence.InsertEvidence(ctx, item); err != nil {
			return releaseapp.BuildAttestationEvidenceReceipt{}, toReleaseContextError(err)
		}
	}
	t.evidence[item.ID] = item
	return releaseapp.BuildAttestationEvidenceReceipt{EvidenceID: item.ID}, nil
}

func (t *ledgerReleaseTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.TenantID) == "" || strings.TrimSpace(event.Kind) == "" || strings.TrimSpace(event.SubjectType) == "" || strings.TrimSpace(event.SubjectID) == "" || event.CreatedAt.IsZero() {
		return releaseapp.ErrValidation
	}
	job := OutboxJob{
		ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, Payload: cloneMap(event.Payload), CreatedAt: event.CreatedAt,
	}
	if err := EnsureOutboxDeduplicationKey(&job); err != nil {
		return toReleaseContextError(err)
	}
	if t.repositories != nil {
		return toReleaseContextError(t.repositories.Outbox.Enqueue(ctx, job))
	}
	t.outbox = append(t.outbox, job)
	return nil
}

func (t *ledgerReleaseTransaction) ContainerImageByRepositoryDigest(_ context.Context, tenantID, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	for _, image := range t.images {
		if image.TenantID == tenantID && image.Repository == repository && image.Digest == digest {
			return containerImageToReleaseContext(image), true, nil
		}
	}
	for _, image := range t.ledger.images {
		if image.TenantID == tenantID && image.Repository == repository && image.Digest == digest {
			return containerImageToReleaseContext(image), true, nil
		}
	}
	return releasedomain.ContainerImage{}, false, nil
}

func (t *ledgerReleaseTransaction) InsertContainerImage(ctx context.Context, image releasedomain.ContainerImage) error {
	legacy := containerImageFromReleaseContext(image)
	if _, exists := t.ledger.images[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if _, exists := t.images[legacy.ID]; exists {
		return releaseapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.SupplyChain.InsertContainerImage(ctx, legacy); err != nil {
			return toReleaseContextError(err)
		}
	}
	t.images[legacy.ID] = legacy
	return nil
}

func (t *ledgerReleaseTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry := domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if t.repositories != nil {
		committed, err := t.repositories.Audit.Append(ctx, entry)
		if err != nil {
			return application.AuditReceipt{}, toReleaseContextError(err)
		}
		entry = committed
	} else if err := t.completeCompatibilityAudit(&entry); err != nil {
		return application.AuditReceipt{}, toReleaseContextError(err)
	}
	t.audit = append(t.audit, entry)
	return application.AuditReceipt{ID: entry.ID}, nil
}

func (t *ledgerReleaseTransaction) completeCompatibilityAudit(entry *domain.AuditChainEntry) error {
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

func (t *ledgerReleaseTransaction) publish() {
	for id, product := range t.products {
		t.ledger.products[id] = product
	}
	for id, project := range t.projects {
		t.ledger.projects[id] = project
	}
	for id, release := range t.releases {
		t.ledger.releases[id] = release
	}
	for id, artifact := range t.artifacts {
		t.ledger.artifacts[id] = artifact
	}
	for id, build := range t.buildRuns {
		t.ledger.buildRuns[id] = build
	}
	for id, attestation := range t.attestations {
		t.ledger.attestations[id] = attestation
	}
	for id, evidence := range t.evidence {
		t.ledger.evidence[id] = evidence
	}
	for id, candidate := range t.candidates {
		t.ledger.candidates[id] = candidate
	}
	for id, image := range t.images {
		t.ledger.images[id] = image
	}
	for _, entry := range t.audit {
		t.ledger.publishCommittedAuditEntryLocked(entry)
	}
}

func (t *ledgerReleaseTransaction) commitCompatibility(ctx context.Context) error {
	products := cloneProductMap(t.ledger.products)
	projects := cloneProjectMap(t.ledger.projects)
	releases := cloneReleaseMap(t.ledger.releases)
	artifacts := cloneArtifactMap(t.ledger.artifacts)
	builds := cloneBuildRunMap(t.ledger.buildRuns)
	attestations := cloneReleaseBuildAttestationMap(t.ledger.attestations)
	evidence := cloneReleaseEvidenceMap(t.ledger.evidence)
	candidates := cloneReleaseCandidateMap(t.ledger.candidates)
	images := cloneContainerImageMap(t.ledger.images)
	chain := cloneAuditChainMap(t.ledger.chain)
	t.publish()
	persist := t.ledger.persistReleaseLedgerStateLocked
	if len(t.buildRuns) > 0 || len(t.attestations) > 0 || len(t.evidence) > 0 || len(t.candidates) > 0 || len(t.images) > 0 {
		persist = t.ledger.persistLocked
	}
	for _, job := range t.outbox {
		if err := t.ledger.enqueueJob(ctx, job); err != nil {
			t.ledger.products = products
			t.ledger.projects = projects
			t.ledger.releases = releases
			t.ledger.artifacts = artifacts
			t.ledger.buildRuns = builds
			t.ledger.attestations = attestations
			t.ledger.evidence = evidence
			t.ledger.candidates = candidates
			t.ledger.images = images
			t.ledger.chain = chain
			return toReleaseContextError(err)
		}
	}
	if err := persist(ctx); err != nil {
		t.ledger.products = products
		t.ledger.projects = projects
		t.ledger.releases = releases
		t.ledger.artifacts = artifacts
		t.ledger.buildRuns = builds
		t.ledger.attestations = attestations
		t.ledger.evidence = evidence
		t.ledger.candidates = candidates
		t.ledger.images = images
		t.ledger.chain = chain
		return toReleaseContextError(err)
	}
	return nil
}

func NewContextAuthorizer(ledger *Ledger) (application.Authorizer, error) {
	if ledger == nil {
		return nil, ErrValidation
	}
	return ledgerContextAuthorizer{ledger: ledger}, nil
}

func cloneProductMap(values map[string]domain.Product) map[string]domain.Product {
	result := make(map[string]domain.Product, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneProjectMap(values map[string]domain.Project) map[string]domain.Project {
	result := make(map[string]domain.Project, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneReleaseMap(values map[string]domain.Release) map[string]domain.Release {
	result := make(map[string]domain.Release, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneArtifactMap(values map[string]domain.Artifact) map[string]domain.Artifact {
	result := make(map[string]domain.Artifact, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneBuildRunMap(values map[string]domain.BuildRun) map[string]domain.BuildRun {
	result := make(map[string]domain.BuildRun, len(values))
	for key, value := range values {
		result[key] = buildRunFromReleaseContext(buildRunToReleaseContext(value))
	}
	return result
}

func cloneReleaseEvidenceMap(values map[string]domain.EvidenceItem) map[string]domain.EvidenceItem {
	result := make(map[string]domain.EvidenceItem, len(values))
	for key, value := range values {
		value.SourceIdentity = cloneMap(value.SourceIdentity)
		value.SubjectRefs = append([]domain.SubjectRef(nil), value.SubjectRefs...)
		value.RelatedEvidenceRefs = append([]domain.EvidenceRef(nil), value.RelatedEvidenceRefs...)
		value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
		value.Tags = append([]string(nil), value.Tags...)
		value.Metadata = cloneMap(value.Metadata)
		value.Warnings = append([]domain.EvidenceNotice(nil), value.Warnings...)
		value.Limitations = append([]string(nil), value.Limitations...)
		result[key] = value
	}
	return result
}

func cloneReleaseCandidateMap(values map[string]domain.ReleaseCandidate) map[string]domain.ReleaseCandidate {
	result := make(map[string]domain.ReleaseCandidate, len(values))
	for key, value := range values {
		mapped, err := releaseCandidateToReleaseContext(value)
		if err != nil {
			result[key] = value
			continue
		}
		result[key] = releaseCandidateFromReleaseContext(mapped)
	}
	return result
}

func cloneContainerImageMap(values map[string]domain.ContainerImage) map[string]domain.ContainerImage {
	result := make(map[string]domain.ContainerImage, len(values))
	for key, value := range values {
		result[key] = containerImageFromReleaseContext(containerImageToReleaseContext(value))
	}
	return result
}
