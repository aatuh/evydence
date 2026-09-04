// Package app owns release-catalog command and query orchestration.
package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const (
	ScopeProductWrite  = "product:write"
	ScopeProductRead   = "product:read"
	ScopeProjectWrite  = "project:write"
	ScopeProjectRead   = "project:read"
	ScopeReleaseWrite  = "release:write"
	ScopeReleaseRead   = "release:read"
	ScopeBuildWrite    = "build:write"
	ScopeBuildRead     = "build:read"
	ScopeEvidenceWrite = "evidence:write"
	ScopeEvidenceRead  = "evidence:read"
)

var (
	ErrValidation = errors.New("validation failed")
	ErrForbidden  = application.ErrForbidden
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
)

// VersionConflictError carries only the safe current revision after the actor
// has been authorized for the release.
type VersionConflictError struct{ CurrentRevision int64 }

func (e VersionConflictError) Error() string {
	return fmt.Sprintf("resource revision conflict (current revision %d)", e.CurrentRevision)
}

func (VersionConflictError) Unwrap() error { return ErrConflict }

func NewVersionConflict(currentRevision int64) error {
	if currentRevision < 1 {
		return ErrConflict
	}
	return VersionConflictError{CurrentRevision: currentRevision}
}

func CurrentRevision(err error) (int64, bool) {
	var conflict VersionConflictError
	if !errors.As(err, &conflict) || conflict.CurrentRevision < 1 {
		return 0, false
	}
	return conflict.CurrentRevision, true
}

type Reader interface {
	ListProducts(context.Context, string) ([]releasedomain.Product, error)
	GetProduct(context.Context, string, string) (releasedomain.Product, error)
	GetProject(context.Context, string, string) (releasedomain.Project, error)
	GetRelease(context.Context, string, string) (releasedomain.Release, error)
	GetArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	GetBuildRun(context.Context, string, string) (releasedomain.BuildRun, error)
	GetReleaseCandidate(context.Context, string, string) (releasedomain.ReleaseCandidate, error)
	ListReleaseCandidates(context.Context, string, string) ([]releasedomain.ReleaseCandidate, error)
}

type CatalogRepository interface {
	ProductBySlug(context.Context, string, string) (releasedomain.Product, bool, error)
	GetProduct(context.Context, string, string) (releasedomain.Product, error)
	InsertProduct(context.Context, releasedomain.Product) error
	GetProject(context.Context, string, string) (releasedomain.Project, error)
	InsertProject(context.Context, releasedomain.Project) error
	ReleaseByVersion(context.Context, string, string, string) (releasedomain.Release, bool, error)
	GetRelease(context.Context, string, string) (releasedomain.Release, error)
	InsertRelease(context.Context, releasedomain.Release) error
	UpdateRelease(context.Context, releasedomain.Release, int64) error
	GetArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ArtifactByDigest(context.Context, string, string) (releasedomain.Artifact, bool, error)
	InsertArtifact(context.Context, releasedomain.Artifact) error
	GetReleaseCandidate(context.Context, string, string) (releasedomain.ReleaseCandidate, error)
	InsertReleaseCandidate(context.Context, releasedomain.ReleaseCandidate) error
	UpdateReleaseCandidateState(context.Context, releasedomain.ReleaseCandidate, int64, string) error
}

// BuildRepository is the release context's transaction-scoped build port.
type BuildRepository interface {
	GetBuildRun(context.Context, string, string) (releasedomain.BuildRun, error)
	InsertBuildRun(context.Context, releasedomain.BuildRun) error
	InsertBuildAttestation(context.Context, releasedomain.BuildAttestation) error
}

// SupplyChainRepository owns container-image registration for this context.
type SupplyChainRepository interface {
	ContainerImageByRepositoryDigest(context.Context, string, string, string) (releasedomain.ContainerImage, bool, error)
	InsertContainerImage(context.Context, releasedomain.ContainerImage) error
}

// ReleaseCandidateReferences is the identifier-only cross-context view needed
// to validate a candidate snapshot without importing foreign aggregates.
type ReleaseCandidateReferences struct {
	BuildIDs    []string
	ArtifactIDs []string
	SBOMIDs     []string
	ScanIDs     []string
	VEXIDs      []string
	ContractIDs []string
	BundleIDs   []string
}

// ReleaseCandidateReferenceValidator is a read-only boundary. Implementations
// must enforce tenant ownership and, where applicable, release ownership. The
// referenced records are immutable; this service rechecks same-context build
// and artifact coordinates inside its mutation transaction.
type ReleaseCandidateReferenceValidator interface {
	ValidateReleaseCandidateReferences(context.Context, string, string, ReleaseCandidateReferences) error
}

// ReleaseCandidateCanonicalizer computes the versioned snapshot digest. The
// candidate passed to it has an empty SnapshotHash.
type ReleaseCandidateCanonicalizer interface {
	HashReleaseCandidate(context.Context, releasedomain.ReleaseCandidate) (string, error)
}

type Transaction interface {
	Catalog() CatalogRepository
	Builds() BuildRepository
	BuildAttestationEvidence() BuildAttestationEvidenceWriter
	SupplyChain() SupplyChainRepository
	Authorization() application.Authorizer
	Audit() application.AuditAppender
	Outbox() application.OutboxEnqueuer
}

type TransactionCommand func(context.Context, Transaction) error

type TransactionRunner interface {
	Execute(context.Context, TransactionCommand) error
}

type Config struct {
	Reader              Reader
	Transactions        TransactionRunner
	Authorizer          application.Authorizer
	CandidateReferences ReleaseCandidateReferenceValidator
	Canonicalizer       ReleaseCandidateCanonicalizer
	AttestationParser   BuildAttestationParser
	PayloadStager       BuildAttestationPayloadStager
	WorkerOwnedParsers  bool
	Clock               application.Clock
	IDs                 application.IDGenerator
}

type Service struct {
	reader              Reader
	transactions        TransactionRunner
	authorizer          application.Authorizer
	candidateReferences ReleaseCandidateReferenceValidator
	canonicalizer       ReleaseCandidateCanonicalizer
	attestationParser   BuildAttestationParser
	payloadStager       BuildAttestationPayloadStager
	workerOwnedParsers  bool
	clock               application.Clock
	ids                 application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.CandidateReferences == nil || config.Canonicalizer == nil || config.AttestationParser == nil || config.PayloadStager == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &Service{
		reader: config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		candidateReferences: config.CandidateReferences, canonicalizer: config.Canonicalizer,
		attestationParser: config.AttestationParser, payloadStager: config.PayloadStager,
		workerOwnedParsers: config.WorkerOwnedParsers,
		clock:              config.Clock, ids: config.IDs,
	}, nil
}

type CreateProductInput struct {
	Name string
	Slug string
}

func (s *Service) CreateProduct(ctx context.Context, actor identitydomain.Actor, input CreateProductInput) (releasedomain.Product, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Product{}, err
	}
	if err := s.authorize(ctx, actor, ScopeProductWrite, application.ResourceReferences{}, false); err != nil {
		return releasedomain.Product{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	if input.Name == "" || input.Slug == "" {
		return releasedomain.Product{}, ErrValidation
	}
	product := releasedomain.Product{ID: s.ids.NewID("prod"), TenantID: actor.TenantID, Name: input.Name, Slug: input.Slug, CreatedAt: s.clock.Now().UTC()}
	err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if _, exists, err := tx.Catalog().ProductBySlug(ctx, actor.TenantID, input.Slug); err != nil {
			return err
		} else if exists {
			return ErrConflict
		}
		if err := tx.Catalog().InsertProduct(ctx, product); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, product.CreatedAt, "product.created", "product", product.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Product{}, err
	}
	return product, nil
}

func (s *Service) ListProducts(ctx context.Context, actor identitydomain.Actor) ([]releasedomain.Product, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeProductRead, application.ResourceReferences{}, true); err != nil {
		return nil, err
	}
	products, err := s.reader.ListProducts(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]releasedomain.Product, 0, len(products))
	for _, product := range products {
		if product.TenantID != actor.TenantID {
			continue
		}
		if err := s.authorize(ctx, actor, ScopeProductRead, application.ResourceReferences{ProductID: product.ID}, false); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return nil, err
		}
		result = append(result, product)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Service) GetProduct(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Product, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Product{}, err
	}
	if err := s.authorize(ctx, actor, ScopeProductRead, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Product{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Product{}, ErrNotFound
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Product{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, id) {
		return releasedomain.Product{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeProductRead, application.ResourceReferences{ProductID: product.ID}, false); err != nil {
		return releasedomain.Product{}, err
	}
	return product, nil
}

type CreateProjectInput struct {
	ProductID string
	Name      string
}

func (s *Service) CreateProject(ctx context.Context, actor identitydomain.Actor, input CreateProjectInput) (releasedomain.Project, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Project{}, err
	}
	if err := s.authorize(ctx, actor, ScopeProjectWrite, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Project{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.Name = strings.TrimSpace(input.Name)
	if input.ProductID == "" || input.Name == "" {
		return releasedomain.Project{}, ErrValidation
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, input.ProductID)
	if err != nil {
		return releasedomain.Project{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, input.ProductID) {
		return releasedomain.Project{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeProjectWrite, application.ResourceReferences{ProductID: product.ID}, false); err != nil {
		return releasedomain.Project{}, err
	}
	project := releasedomain.Project{ID: s.ids.NewID("proj"), TenantID: actor.TenantID, ProductID: product.ID, Name: input.Name, CreatedAt: s.clock.Now().UTC()}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := tx.Catalog().GetProduct(ctx, actor.TenantID, product.ID)
		if err != nil {
			return err
		}
		if !productBelongsToTenant(current, actor.TenantID, product.ID) {
			return ErrNotFound
		}
		if !sameProductCoordinates(current, product) {
			return ErrConflict
		}
		if err := tx.Catalog().InsertProject(ctx, project); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, project.CreatedAt, "project.created", "project", project.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return project, nil
}

func (s *Service) GetProject(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Project, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Project{}, err
	}
	if err := s.authorize(ctx, actor, ScopeProjectRead, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Project{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Project{}, ErrNotFound
	}
	project, err := s.reader.GetProject(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Project{}, err
	}
	if !projectBelongsToTenant(project, actor.TenantID, id) || strings.TrimSpace(project.ProductID) == "" {
		return releasedomain.Project{}, ErrNotFound
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, project.ProductID)
	if err != nil {
		return releasedomain.Project{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, project.ProductID) {
		return releasedomain.Project{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeProjectRead, application.ResourceReferences{ProductID: project.ProductID, ProjectID: project.ID}, false); err != nil {
		return releasedomain.Project{}, err
	}
	return project, nil
}

type CreateReleaseInput struct {
	ProductID string
	Version   string
}

func (s *Service) CreateRelease(ctx context.Context, actor identitydomain.Actor, input CreateReleaseInput) (releasedomain.Release, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Release{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Release{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.Version = strings.TrimSpace(input.Version)
	if input.ProductID == "" || input.Version == "" {
		return releasedomain.Release{}, ErrValidation
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, input.ProductID)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, input.ProductID) {
		return releasedomain.Release{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{ProductID: product.ID}, false); err != nil {
		return releasedomain.Release{}, err
	}
	release, err := releasedomain.NewRelease(s.ids.NewID("rel"), actor.TenantID, product.ID, input.Version, s.clock.Now())
	if err != nil {
		return releasedomain.Release{}, ErrValidation
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		currentProduct, err := tx.Catalog().GetProduct(ctx, actor.TenantID, product.ID)
		if err != nil {
			return err
		}
		if !productBelongsToTenant(currentProduct, actor.TenantID, product.ID) {
			return ErrNotFound
		}
		if !sameProductCoordinates(currentProduct, product) {
			return ErrConflict
		}
		if existing, exists, err := tx.Catalog().ReleaseByVersion(ctx, actor.TenantID, product.ID, input.Version); err != nil {
			return err
		} else if exists {
			if existing.TenantID != actor.TenantID || strings.TrimSpace(existing.ID) == "" {
				return ErrNotFound
			}
			if existing.ProductID != product.ID || existing.Version != input.Version {
				return ErrConflict
			}
			return ErrConflict
		}
		if err := tx.Catalog().InsertRelease(ctx, release); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, release.CreatedAt, "release.created", "release", release.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return release, nil
}

func (s *Service) GetRelease(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Release, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Release{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseRead, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Release{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, id) || strings.TrimSpace(release.ProductID) == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, release.ProductID)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, release.ProductID) {
		return releasedomain.Release{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeReleaseRead, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
		return releasedomain.Release{}, err
	}
	return release, nil
}

func (s *Service) FreezeRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64) (releasedomain.Release, error) {
	return s.transitionRelease(ctx, actor, id, expectedRevision, releasedomain.ReleaseStateDraftValue, "release.frozen", func(release releasedomain.Release, at time.Time) (releasedomain.Release, error) {
		return release.Freeze(at)
	})
}

func (s *Service) ApproveRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64) (releasedomain.Release, error) {
	return s.transitionRelease(ctx, actor, id, expectedRevision, releasedomain.ReleaseStateFrozenValue, "release.approved", func(release releasedomain.Release, at time.Time) (releasedomain.Release, error) {
		return release.Approve(at)
	})
}

func (s *Service) transitionRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64, expectedState, eventType string, transition func(releasedomain.Release, time.Time) (releasedomain.Release, error)) (releasedomain.Release, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Release{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Release{}, err
	}
	if expectedRevision < 1 {
		return releasedomain.Release{}, ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, id) || strings.TrimSpace(release.ProductID) == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, release.ProductID)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, release.ProductID) {
		return releasedomain.Release{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
		return releasedomain.Release{}, err
	}
	if release.Revision != expectedRevision {
		return releasedomain.Release{}, NewVersionConflict(release.Revision)
	}
	if release.State.String() != expectedState {
		return releasedomain.Release{}, ErrConflict
	}
	transitionedAt := s.clock.Now().UTC()
	var updated releasedomain.Release
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := tx.Catalog().GetRelease(ctx, actor.TenantID, release.ID)
		if err != nil {
			return err
		}
		if !releaseBelongsToTenant(current, actor.TenantID, release.ID) {
			return ErrNotFound
		}
		if !sameReleaseCoordinates(current, release) {
			return ErrConflict
		}
		if current.Revision != expectedRevision {
			return NewVersionConflict(current.Revision)
		}
		if current.State.String() != expectedState {
			return ErrConflict
		}
		updated, err = transition(current, transitionedAt)
		if err != nil {
			return ErrConflict
		}
		if err := tx.Catalog().UpdateRelease(ctx, updated, expectedRevision); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, transitionedAt, eventType, "release", updated.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return updated, nil
}

type RegisterArtifactInput struct {
	Name      string
	MediaType string
	Digest    string
	Size      int64
}

func (s *Service) RegisterArtifact(ctx context.Context, actor identitydomain.Actor, input RegisterArtifactInput) (releasedomain.Artifact, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Artifact{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Artifact{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	input.MediaType = strings.TrimSpace(input.MediaType)
	input.Digest = strings.TrimSpace(input.Digest)
	if input.Name == "" || input.MediaType == "" || !validDigest(input.Digest) || input.Size < 0 {
		return releasedomain.Artifact{}, ErrValidation
	}
	artifact := releasedomain.Artifact{ID: s.ids.NewID("art"), TenantID: actor.TenantID, Name: input.Name, MediaType: input.MediaType, Size: input.Size, Digest: input.Digest, CreatedAt: s.clock.Now().UTC()}
	err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if existing, exists, err := tx.Catalog().ArtifactByDigest(ctx, actor.TenantID, input.Digest); err != nil {
			return err
		} else if exists {
			if existing.TenantID != actor.TenantID || strings.TrimSpace(existing.ID) == "" {
				return ErrNotFound
			}
			if existing.Digest != input.Digest {
				return ErrConflict
			}
			if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: existing.ID}}); err != nil {
				return err
			}
			artifact = existing
			return nil
		}
		if err := tx.Catalog().InsertArtifact(ctx, artifact); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, artifact.CreatedAt, "artifact.created", "artifact", artifact.ID, artifact.Digest))
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return artifact, nil
}

func (s *Service) GetArtifact(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Artifact, error) {
	if err := contextError(ctx); err != nil {
		return releasedomain.Artifact{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return releasedomain.Artifact{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Artifact{}, ErrNotFound
	}
	artifact, err := s.reader.GetArtifact(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	if !artifactBelongsToTenant(artifact, actor.TenantID, id) {
		return releasedomain.Artifact{}, ErrNotFound
	}
	if !validDigest(artifact.Digest) || artifact.Size < 0 {
		return releasedomain.Artifact{}, ErrConflict
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ArtifactID: artifact.ID}, false); err != nil {
		return releasedomain.Artifact{}, err
	}
	return artifact, nil
}

func (s *Service) authorize(ctx context.Context, actor identitydomain.Actor, scope string, resources application.ResourceReferences, scopeOnly bool) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources, ScopeOnly: scopeOnly})
}

func (s *Service) auditEvent(actor identitydomain.Actor, occurredAt time.Time, entryType, subjectType, subjectID, payloadHash string) application.AuditEvent {
	actorType, actorID := auditActor(actor)
	return application.AuditEvent{
		ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType,
		SubjectType: subjectType, SubjectID: subjectID, ActorType: actorType, ActorID: actorID,
		OccurredAt: occurredAt.UTC(), PayloadHash: payloadHash,
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrValidation
	}
	return ctx.Err()
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
