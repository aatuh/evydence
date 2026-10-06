// Package app owns accepted-evidence command and query orchestration.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const (
	ScopeEvidenceWrite = "evidence:write"
	ScopeEvidenceRead  = "evidence:read"
	ScopeSecurityWrite = "security:write"

	EvidenceDocumentLimit int64 = 20 << 20

	PayloadLifecycleVersion = "object-payload.v1"
	PayloadStatusStaged     = "staged"
	PayloadStatusFinalized  = "finalized"
	parserNormalizationType = "parser_normalization"

	legacyCanonicalOriginDetail = evidencedomain.LegacyCanonicalOriginDetailKey
)

var (
	ErrValidation = errors.New("validation failed")
	ErrForbidden  = application.ErrForbidden
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
)

type EvidenceScope struct {
	ProductID              string
	ProjectID              string
	ReleaseID              string
	BuildID                string
	DeploymentID           string
	AllowPendingDeployment bool
}

type StagedPayload struct {
	TenantID    string
	Digest      string
	Size        int64
	MediaType   string
	StagingKey  string
	FinalKey    string
	Status      string
	FailureCode string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	FinalizedAt *time.Time
	FailedAt    *time.Time
	OrphanedAt  *time.Time
}

func (p StagedPayload) Present() bool {
	return p.TenantID != "" || p.Digest != "" || p.Size != 0 || p.MediaType != "" || p.StagingKey != "" || p.FinalKey != "" || p.Status != "" || p.FailureCode != "" || !p.CreatedAt.IsZero() || !p.UpdatedAt.IsZero() || p.FinalizedAt != nil || p.FailedAt != nil || p.OrphanedAt != nil
}

func (p StagedPayload) Reference() string {
	if strings.TrimSpace(p.FinalKey) == "" {
		return ""
	}
	return "object://" + p.FinalKey
}

type Reader interface {
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateLinkTarget(context.Context, string, string, string) error
	// ValidateArtifactReference confirms tenant ownership and, when digest is
	// nonempty, semantic equality with the registered artifact digest.
	ValidateArtifactReference(context.Context, string, string, string) error
	GetEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	GetSBOM(context.Context, string, string) (evidencedomain.SBOM, error)
	GetOpenAPIContract(context.Context, string, string) (evidencedomain.OpenAPIContract, error)
	ListEvidence(context.Context, string, string, string) ([]evidencedomain.EvidenceItem, error)
	ListLifecycleEvents(context.Context, string, string) ([]evidencedomain.EvidenceLifecycleEvent, error)
}

type Repository interface {
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateLinkTarget(context.Context, string, string, string) error
	// GetEvidence returns the tenant-owned durable row and keeps its link/scope
	// state stable for the surrounding transaction.
	GetEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	InsertEvidence(context.Context, evidencedomain.EvidenceItem) error
	RecordSupersession(context.Context, evidencedomain.EvidenceItem, evidencedomain.EvidenceItem) error
	// CompareAndSwapEvidenceLinks changes only evidence links if the complete
	// expected prior link/scope state is still current.
	CompareAndSwapEvidenceLinks(context.Context, evidencedomain.EvidenceItem, evidencedomain.EvidenceItem) error
	AppendLifecycle(context.Context, evidencedomain.EvidenceLifecycleEvent) error
}

// IngestionRepository is the evidence-context view of legacy raw document and
// diff persistence. The compatibility adapter may still store these records
// through the legacy Risk repository while ownership migrates.
type IngestionRepository interface {
	// ValidateArtifactReference repeats the artifact ownership/digest check in
	// the command transaction before any evidence effects are persisted.
	ValidateArtifactReference(context.Context, string, string, string) error
	// Parsed projection reads are tenant-scoped and stable for the surrounding
	// transaction so generated diffs describe the authorized durable inputs.
	GetSBOM(context.Context, string, string) (evidencedomain.SBOM, error)
	GetOpenAPIContract(context.Context, string, string) (evidencedomain.OpenAPIContract, error)
	InsertSBOM(context.Context, evidencedomain.SBOM) error
	InsertVulnerabilityScan(context.Context, evidencedomain.VulnerabilityScan) error
	InsertOpenAPIContract(context.Context, evidencedomain.OpenAPIContract) error
	InsertVEXDocument(context.Context, evidencedomain.VEXDocument) error
	InsertVEXImportReport(context.Context, evidencedomain.VEXImportReport) error
	InsertSecurityScan(context.Context, evidencedomain.SecurityScan) error
	InsertManualSecurityDocument(context.Context, evidencedomain.ManualSecurityDocument) error
	InsertSBOMDiff(context.Context, evidencedomain.SBOMDiff) error
	InsertContractDiff(context.Context, evidencedomain.ContractDiff) error
}

type PayloadRecorder interface {
	RecordStagedPayload(context.Context, StagedPayload) error
}

type Transaction interface {
	application.Authorizer
	Evidence() Repository
	Ingestion() IngestionRepository
	Payloads() PayloadRecorder
	Outbox() application.OutboxEnqueuer
	Audit() application.AuditAppender
}

type TransactionCommand func(context.Context, Transaction) error

type TransactionRunner interface {
	Execute(context.Context, TransactionCommand) error
}

// ProjectionRefresher makes worker-owned parsed records visible before a
// command derives immutable output from them. Production adapters bind the
// refresh to an already-active command transaction when one exists.
type ProjectionRefresher interface {
	RefreshWorkerProjection(context.Context, string) error
}

type ObjectIngestion interface {
	StagePayload(context.Context, string, string, string, []byte) (StagedPayload, error)
	ValidateStagedPayload(context.Context, StagedPayload) error
}

type SourceObjectIngestion interface {
	StagePayloadSource(context.Context, string, string, PayloadSource) (StagedPayload, error)
}

type Canonicalizer interface {
	HashEvidence(context.Context, evidencedomain.EvidenceItem) (string, error)
}

// LifecycleSanitizer removes secrets and sensitive fields before append-only
// lifecycle details cross the persistence or API boundary.
type LifecycleSanitizer interface {
	SanitizeLifecycle(context.Context, string, map[string]any) (string, map[string]any, error)
}

type Config struct {
	Reader                       Reader
	Transactions                 TransactionRunner
	ProjectionRefresher          ProjectionRefresher
	Authorizer                   application.Authorizer
	Objects                      ObjectIngestion
	SourceObjects                SourceObjectIngestion
	Parser                       PayloadParser
	VulnerabilityScanScopeProber VulnerabilityScanScopeProber
	Canonicalizer                Canonicalizer
	LifecycleSanitizer           LifecycleSanitizer
	CanonicalizationProfile      string
	Clock                        application.Clock
	IDs                          application.IDGenerator
	WorkerOwnedParsers           bool
}

type Service struct {
	creation                     *EvidenceCreationCommands
	reader                       Reader
	transactions                 TransactionRunner
	projectionRefresher          ProjectionRefresher
	authorizer                   application.Authorizer
	objects                      ObjectIngestion
	sourceObjects                SourceObjectIngestion
	parser                       PayloadParser
	vulnerabilityScanScopeProber VulnerabilityScanScopeProber
	canonicalizer                Canonicalizer
	lifecycleSanitizer           LifecycleSanitizer
	canonicalizationProfile      string
	clock                        application.Clock
	ids                          application.IDGenerator
	workerOwnedParsers           bool
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.Objects == nil || config.SourceObjects == nil || config.Parser == nil || config.VulnerabilityScanScopeProber == nil || config.Canonicalizer == nil || config.LifecycleSanitizer == nil || config.Clock == nil || config.IDs == nil || strings.TrimSpace(config.CanonicalizationProfile) == "" {
		return nil, ErrValidation
	}
	creation, err := NewEvidenceCreationCommands(EvidenceCreationCommandConfig{
		Reader: config.Reader, Transactions: evidenceCreationTransactions{config.Transactions},
		Authorizer: config.Authorizer, Payloads: config.Objects, Canonicalizer: config.Canonicalizer,
		CanonicalizationProfile: config.CanonicalizationProfile, Clock: config.Clock, IDs: config.IDs,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		creation: creation,
		reader:   config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		projectionRefresher: config.ProjectionRefresher,
		objects:             config.Objects, sourceObjects: config.SourceObjects, parser: config.Parser, vulnerabilityScanScopeProber: config.VulnerabilityScanScopeProber,
		canonicalizer: config.Canonicalizer, lifecycleSanitizer: config.LifecycleSanitizer,
		canonicalizationProfile: strings.TrimSpace(config.CanonicalizationProfile), clock: config.Clock, ids: config.IDs,
		workerOwnedParsers: config.WorkerOwnedParsers,
	}, nil
}

type CreateEvidenceInput struct {
	ProductID        string
	ProjectID        string
	ReleaseID        string
	BuildID          string
	DeploymentID     string
	Type             string
	Subtype          string
	Title            string
	SourceSystem     string
	SourceIdentity   map[string]any
	CollectorID      string
	ObservedAt       time.Time
	PayloadRef       string
	PayloadHash      string
	PayloadMediaType string
	PayloadSize      int64
	StagedPayload    StagedPayload
	SubjectRefs      []evidencedomain.SubjectRef
	Metadata         map[string]any
	Tags             []string
	Limitations      []string
}

func (s *Service) CreateEvidence(ctx context.Context, actor identitydomain.Actor, input CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	return s.creation.CreateEvidence(ctx, actor, input)
}

func (s *Service) prepareEvidence(ctx context.Context, actor identitydomain.Actor, input CreateEvidenceInput) (preparedEvidence, error) {
	return s.prepareEvidenceForScope(ctx, actor, ScopeEvidenceWrite, input)
}

func (s *Service) prepareEvidenceForScope(ctx context.Context, actor identitydomain.Actor, authorizationScope string, input CreateEvidenceInput) (preparedEvidence, error) {
	return s.creation.preparer.prepareEvidenceForScope(ctx, actor, authorizationScope, input)
}

func (s *Service) persistPreparedEvidence(ctx context.Context, tx Transaction, actor identitydomain.Actor, prepared *preparedEvidence) error {
	return s.creation.preparer.persistPreparedEvidence(ctx, evidenceCreationTransaction{tx}, actor, prepared)
}

func (s *Service) GetEvidence(ctx context.Context, actor identitydomain.Actor, id string) (evidencedomain.EvidenceItem, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencedomain.EvidenceItem{}, ErrNotFound
	}
	item, err := s.reader.GetEvidence(ctx, actor.TenantID, id)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, id, item); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, evidenceReferences(item), false); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return cloneEvidence(item), nil
}

func (s *Service) ListEvidence(ctx context.Context, actor identitydomain.Actor, releaseID, evidenceType string) ([]evidencedomain.EvidenceItem, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return nil, err
	}
	items, err := s.reader.ListEvidence(ctx, actor.TenantID, strings.TrimSpace(releaseID), strings.TrimSpace(evidenceType))
	if err != nil {
		return nil, err
	}
	result := make([]evidencedomain.EvidenceItem, 0, len(items))
	for _, item := range items {
		if item.TenantID != actor.TenantID {
			continue
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceRead, evidenceReferences(item), false); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return nil, err
		}
		result = append(result, cloneEvidence(item))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Service) SupersedeEvidence(ctx context.Context, a identitydomain.Actor, id, replacement, reason string) (evidencedomain.EvidenceItem, error) {
	c, err := s.relationshipCommands()
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return c.SupersedeEvidence(ctx, a, id, replacement, reason)
}
func (s *Service) LinkEvidence(ctx context.Context, a identitydomain.Actor, id, kind, target string) (evidencedomain.EvidenceItem, error) {
	c, err := s.relationshipCommands()
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return c.LinkEvidence(ctx, a, id, kind, target)
}
func (s *Service) RecordLifecycleEvent(ctx context.Context, a identitydomain.Actor, id string, in RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error) {
	c, err := s.relationshipCommands()
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	return c.RecordLifecycleEvent(ctx, a, id, in)
}

func (s *Service) ListLifecycleEvents(ctx context.Context, actor identitydomain.Actor, evidenceID string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return nil, err
	}
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return nil, ErrNotFound
	}
	item, err := s.reader.GetEvidence(ctx, actor.TenantID, evidenceID)
	if err != nil {
		return nil, err
	}
	if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, evidenceID, item); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, evidenceReferences(item), false); err != nil {
		return nil, err
	}
	events, err := s.reader.ListLifecycleEvents(ctx, actor.TenantID, item.ID)
	if err != nil {
		return nil, err
	}
	result := make([]evidencedomain.EvidenceLifecycleEvent, 0, len(events))
	for _, event := range events {
		if err := validateReturnedLifecycleEvent(actor.TenantID, item.ID, event); err != nil {
			return nil, err
		}
		detailsForOutput := cloneMap(event.Details)
		delete(detailsForOutput, legacyCanonicalOriginDetail)
		reason, details, err := s.lifecycleSanitizer.SanitizeLifecycle(ctx, event.Reason, detailsForOutput)
		if err != nil {
			return nil, err
		}
		event.Reason = reason
		event.Details = details
		result = append(result, cloneLifecycleEvent(event))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *Service) authorize(ctx context.Context, actor identitydomain.Actor, scope string, resources application.ResourceReferences, scopeOnly bool) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources, ScopeOnly: scopeOnly})
}

func (s *Service) validateAndAuthorizeArtifactReference(ctx context.Context, actor identitydomain.Actor, scope, artifactID, digest string) error {
	return s.creation.preparer.validateAndAuthorizeArtifactReference(ctx, actor, scope, artifactID, digest)
}

func evidenceReferences(item evidencedomain.EvidenceItem) application.ResourceReferences {
	return application.ResourceReferences{
		ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
		BuildID: item.BuildID, DeploymentID: item.DeploymentID,
	}
}

func resourceReferences(scope EvidenceScope) application.ResourceReferences {
	deploymentID := scope.DeploymentID
	if scope.AllowPendingDeployment {
		deploymentID = ""
	}
	return application.ResourceReferences{
		ProductID: scope.ProductID, ProjectID: scope.ProjectID, ReleaseID: scope.ReleaseID,
		BuildID: scope.BuildID, DeploymentID: deploymentID,
	}
}

type evidenceScopeValidator interface {
	ValidateScope(context.Context, string, EvidenceScope) error
}

func validateReturnedEvidence(ctx context.Context, validator evidenceScopeValidator, tenantID, requestedID string, item evidencedomain.EvidenceItem) error {
	if item.TenantID != tenantID || item.ID != requestedID || strings.TrimSpace(item.TenantID) != item.TenantID || strings.TrimSpace(item.ID) != item.ID {
		return ErrConflict
	}
	for _, coordinate := range []string{item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID} {
		if strings.TrimSpace(coordinate) != coordinate {
			return ErrConflict
		}
	}
	for _, reference := range item.RelatedEvidenceRefs {
		if reference.Type == "" || reference.ID == "" || strings.TrimSpace(reference.Type) != reference.Type || strings.TrimSpace(reference.ID) != reference.ID || strings.TrimSpace(reference.Relationship) != reference.Relationship {
			return ErrConflict
		}
	}
	if strings.TrimSpace(item.Supersedes) != item.Supersedes || strings.TrimSpace(item.SupersededBy) != item.SupersededBy {
		return ErrConflict
	}
	if err := validator.ValidateScope(ctx, tenantID, evidenceScope(item)); err != nil {
		return err
	}
	return nil
}

func validateReturnedLifecycleEvent(tenantID, evidenceID string, event evidencedomain.EvidenceLifecycleEvent) error {
	if event.TenantID != tenantID || event.EvidenceID != evidenceID || event.ID == "" || event.Action.IsZero() ||
		strings.TrimSpace(event.ID) != event.ID || strings.TrimSpace(event.TenantID) != event.TenantID ||
		strings.TrimSpace(event.EvidenceID) != event.EvidenceID || strings.TrimSpace(event.ReplacementID) != event.ReplacementID {
		return ErrConflict
	}
	return nil
}

func workerOwnedEvidenceType(evidenceType string) bool {
	return evidencedomain.RequiresWorkerProjection(evidenceType)
}

type canonicalRelationshipOrigin struct {
	ProductID           string                       `json:"product_id,omitempty"`
	ProjectID           string                       `json:"project_id,omitempty"`
	ReleaseID           string                       `json:"release_id,omitempty"`
	BuildID             string                       `json:"build_id,omitempty"`
	DeploymentID        string                       `json:"deployment_id,omitempty"`
	RelatedEvidenceRefs []evidencedomain.EvidenceRef `json:"related_evidence_refs,omitempty"`
	Supersedes          string                       `json:"supersedes,omitempty"`
	SupersededBy        string                       `json:"superseded_by,omitempty"`
}

func canonicalOriginFromEvidence(item evidencedomain.EvidenceItem) canonicalRelationshipOrigin {
	return canonicalRelationshipOrigin{
		ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
		BuildID: item.BuildID, DeploymentID: item.DeploymentID,
		RelatedEvidenceRefs: append([]evidencedomain.EvidenceRef(nil), item.RelatedEvidenceRefs...),
		Supersedes:          item.Supersedes, SupersededBy: item.SupersededBy,
	}
}

func applyCanonicalRelationshipOrigin(item evidencedomain.EvidenceItem, origin canonicalRelationshipOrigin) evidencedomain.EvidenceItem {
	item.ProductID = origin.ProductID
	item.ProjectID = origin.ProjectID
	item.ReleaseID = origin.ReleaseID
	item.BuildID = origin.BuildID
	item.DeploymentID = origin.DeploymentID
	item.RelatedEvidenceRefs = append([]evidencedomain.EvidenceRef(nil), origin.RelatedEvidenceRefs...)
	item.Supersedes = origin.Supersedes
	item.SupersededBy = origin.SupersededBy
	return item
}

func decodeCanonicalRelationshipOrigin(value any) (canonicalRelationshipOrigin, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return canonicalRelationshipOrigin{}, err
	}
	var origin canonicalRelationshipOrigin
	if err := json.Unmarshal(body, &origin); err != nil {
		return canonicalRelationshipOrigin{}, err
	}
	for _, coordinate := range []string{origin.ProductID, origin.ProjectID, origin.ReleaseID, origin.BuildID, origin.DeploymentID, origin.Supersedes, origin.SupersededBy} {
		if strings.TrimSpace(coordinate) != coordinate {
			return canonicalRelationshipOrigin{}, ErrValidation
		}
	}
	for _, reference := range origin.RelatedEvidenceRefs {
		if reference.Type == "" || reference.ID == "" || strings.TrimSpace(reference.Type) != reference.Type || strings.TrimSpace(reference.ID) != reference.ID || strings.TrimSpace(reference.Relationship) != reference.Relationship {
			return canonicalRelationshipOrigin{}, ErrValidation
		}
	}
	return origin, nil
}

func isDeploymentEvent(evidenceType, subtype string) bool {
	return strings.TrimSpace(evidenceType) == "deployment" && strings.TrimSpace(subtype) == "event"
}

func normalizeSubjectRefs(refs []evidencedomain.SubjectRef) ([]evidencedomain.SubjectRef, error) {
	if refs == nil {
		return nil, nil
	}
	result := make([]evidencedomain.SubjectRef, 0, len(refs))
	for _, ref := range refs {
		ref.Type = strings.TrimSpace(ref.Type)
		ref.ID = strings.TrimSpace(ref.ID)
		ref.Digest = strings.TrimSpace(ref.Digest)
		if ref.Type == "" {
			return nil, ErrValidation
		}
		result = append(result, ref)
	}
	return result, nil
}

func canonicalSupportedSubjectDigest(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") {
		return "", false
	}
	canonical := strings.ToLower(value)
	if !validDigest(canonical) {
		return "", false
	}
	return canonical, true
}

func subjectReferenceScope(ref evidencedomain.SubjectRef) (EvidenceScope, application.ResourceReferences, error) {
	switch ref.Type {
	case "product":
		return EvidenceScope{ProductID: ref.ID}, application.ResourceReferences{ProductID: ref.ID}, nil
	case "project":
		return EvidenceScope{ProjectID: ref.ID}, application.ResourceReferences{ProjectID: ref.ID}, nil
	case "release":
		return EvidenceScope{ReleaseID: ref.ID}, application.ResourceReferences{ReleaseID: ref.ID}, nil
	case "build":
		return EvidenceScope{BuildID: ref.ID}, application.ResourceReferences{BuildID: ref.ID}, nil
	case "deployment":
		return EvidenceScope{DeploymentID: ref.ID}, application.ResourceReferences{DeploymentID: ref.ID}, nil
	default:
		return EvidenceScope{}, application.ResourceReferences{}, ErrValidation
	}
}

func withEvidenceOriginRefs(refs []evidencedomain.SubjectRef, scope EvidenceScope) []evidencedomain.SubjectRef {
	result := append([]evidencedomain.SubjectRef(nil), refs...)
	for _, ref := range []evidencedomain.SubjectRef{
		{Type: "product", ID: scope.ProductID},
		{Type: "project", ID: scope.ProjectID},
		{Type: "release", ID: scope.ReleaseID},
		{Type: "build", ID: scope.BuildID},
		{Type: "deployment", ID: scope.DeploymentID},
	} {
		if ref.ID == "" || containsSubjectRef(result, ref.Type, ref.ID) {
			continue
		}
		result = append(result, ref)
	}
	return result
}

func containsSubjectRef(refs []evidencedomain.SubjectRef, subjectType, subjectID string) bool {
	for _, ref := range refs {
		if ref.Type == subjectType && ref.ID == subjectID {
			return true
		}
	}
	return false
}

func lifecycleState(value string) evidencedomain.EvidenceLifecycleState {
	state, _ := evidencedomain.ParseEvidenceLifecycleState(value)
	return state
}

func evidenceScope(item evidencedomain.EvidenceItem) EvidenceScope {
	return EvidenceScope{
		ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
		BuildID: item.BuildID, DeploymentID: item.DeploymentID,
	}
}

func cloneEvidence(value evidencedomain.EvidenceItem) evidencedomain.EvidenceItem {
	value.SourceIdentity = cloneMap(value.SourceIdentity)
	value.SubjectRefs = append([]evidencedomain.SubjectRef(nil), value.SubjectRefs...)
	value.RelatedEvidenceRefs = append([]evidencedomain.EvidenceRef(nil), value.RelatedEvidenceRefs...)
	value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
	value.Tags = append([]string(nil), value.Tags...)
	value.Metadata = cloneMap(value.Metadata)
	value.Warnings = append([]evidencedomain.EvidenceNotice(nil), value.Warnings...)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneLifecycleEvent(value evidencedomain.EvidenceLifecycleEvent) evidencedomain.EvidenceLifecycleEvent {
	value.Details = cloneMap(value.Details)
	return value
}

func auditActorID(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return actor.CollectorID
	}
	if actor.UserID != "" {
		return actor.UserID
	}
	return actor.KeyID
}

func auditActorType(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func cloneMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = cloneEvidenceJSONValue(item)
	}
	return result
}

// Copy the mutable JSON shapes produced by input decoding and parser adapters
// without converting numbers or changing empty containers in canonical inputs.
func cloneEvidenceJSONValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		if value == nil {
			return value
		}
		result := make(map[string]any, len(value))
		for key, item := range value {
			result[key] = cloneEvidenceJSONValue(item)
		}
		return result
	case []any:
		if value == nil {
			return value
		}
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = cloneEvidenceJSONValue(item)
		}
		return result
	case []string:
		return append(value[:0:0], value...)
	case []map[string]any:
		if value == nil {
			return value
		}
		result := make([]map[string]any, len(value))
		for index, item := range value {
			result[index] = cloneEvidenceJSONValue(item).(map[string]any)
		}
		return result
	default:
		return value
	}
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
	}
	sort.Strings(result)
	return result
}

func nonEmpty(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
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
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
