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
	productCommands          *ProductCommands
	buildAttestationCommands *BuildAttestationCommands
	reader                   Reader
	transactions             TransactionRunner
	authorizer               application.Authorizer
	candidateReferences      ReleaseCandidateReferenceValidator
	canonicalizer            ReleaseCandidateCanonicalizer
	clock                    application.Clock
	ids                      application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.CandidateReferences == nil || config.Canonicalizer == nil || config.AttestationParser == nil || config.PayloadStager == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	productCommands, err := NewProductCommands(ProductCommandConfig{
		Authorizer: config.Authorizer, Transactions: releaseProductTransactions{runner: config.Transactions},
		Clock: config.Clock, IDs: config.IDs,
	})
	if err != nil {
		return nil, err
	}
	attestations, err := NewBuildAttestationCommands(BuildAttestationCommandConfig{
		Reader: config.Reader, Transactions: releaseBuildAttestationTransactions{runner: config.Transactions},
		Authorizer: config.Authorizer, AttestationParser: config.AttestationParser, PayloadStager: config.PayloadStager,
		WorkerOwnedParsers: config.WorkerOwnedParsers, Clock: config.Clock, IDs: config.IDs,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		productCommands:          productCommands,
		buildAttestationCommands: attestations,
		reader:                   config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		candidateReferences: config.CandidateReferences, canonicalizer: config.Canonicalizer,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

type CreateProductInput struct {
	Name string
	Slug string
}

func (s *Service) CreateProduct(ctx context.Context, actor identitydomain.Actor, input CreateProductInput) (releasedomain.Product, error) {
	return s.productCommands.CreateProduct(ctx, actor, input)
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
	commands, err := NewProjectCommands(ProjectCommandConfig{
		Reader: s.reader, Authorizer: s.authorizer,
		Transactions: releaseProjectTransactions{runner: s.transactions},
		Clock:        s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return commands.CreateProject(ctx, actor, input)
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
	commands, err := NewReleaseCommands(ReleaseCommandConfig{
		Reader: s.reader, Authorizer: s.authorizer,
		Transactions: releaseCreationTransactions{runner: s.transactions},
		Clock:        s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return commands.CreateRelease(ctx, actor, input)
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
	commands, err := NewReleaseStateCommands(ReleaseStateCommandConfig{
		Reader: s.reader, Authorizer: s.authorizer,
		Transactions: releaseStateTransactions{runner: s.transactions},
		Clock:        s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return commands.FreezeRelease(ctx, actor, id, expectedRevision)
}

func (s *Service) ApproveRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64) (releasedomain.Release, error) {
	commands, err := NewReleaseStateCommands(ReleaseStateCommandConfig{
		Reader: s.reader, Authorizer: s.authorizer,
		Transactions: releaseStateTransactions{runner: s.transactions},
		Clock:        s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return commands.ApproveRelease(ctx, actor, id, expectedRevision)
}

type RegisterArtifactInput struct {
	Name      string
	MediaType string
	Digest    string
	Size      int64
}

func (s *Service) RegisterArtifact(ctx context.Context, actor identitydomain.Actor, input RegisterArtifactInput) (releasedomain.Artifact, error) {
	commands, err := NewArtifactCommands(ArtifactCommandConfig{
		Authorizer:   s.authorizer,
		Transactions: releaseArtifactTransactions{runner: s.transactions},
		Clock:        s.clock, IDs: s.ids,
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return commands.RegisterArtifact(ctx, actor, input)
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
	return auditEventFor(s.ids, actor, occurredAt, entryType, subjectType, subjectID, payloadHash)
}

func auditEventFor(ids application.IDGenerator, actor identitydomain.Actor, occurredAt time.Time, entryType, subjectType, subjectID, payloadHash string) application.AuditEvent {
	actorType, actorID := auditActor(actor)
	return application.AuditEvent{
		ID: ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType,
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
