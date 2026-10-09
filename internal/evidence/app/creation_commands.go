package app

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// EvidenceCreationReader exposes only existence and coherent ownership checks,
// not parsed documents, lifecycle queries, or arbitrary evidence reads.
type EvidenceCreationReader interface {
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateArtifactReference(context.Context, string, string, string) error
}

type EvidenceCreationPayloadValidator interface {
	ValidateStagedPayload(context.Context, StagedPayload) error
}

// EvidenceCreationTransaction binds validation and authorization to the same
// transaction as evidence, payload, outbox, and audit effects.
type EvidenceCreationTransaction interface {
	EvidenceCreationReader
	application.Authorizer
	application.AuditAppender
	application.OutboxEnqueuer
	PayloadRecorder
	InsertEvidence(context.Context, evidencedomain.EvidenceItem) error
}

type EvidenceCreationTransactionRunner interface {
	ExecuteEvidenceCreation(context.Context, func(context.Context, EvidenceCreationTransaction) error) error
}

type EvidenceCreationCommandConfig struct {
	Reader                  EvidenceCreationReader
	Transactions            EvidenceCreationTransactionRunner
	Authorizer              application.Authorizer
	Payloads                EvidenceCreationPayloadValidator
	Canonicalizer           Canonicalizer
	CanonicalizationProfile string
	Clock                   application.Clock
	IDs                     application.IDGenerator
}

type EvidenceCreationCommands struct {
	preparer     evidencePreparer
	transactions EvidenceCreationTransactionRunner
}

type evidencePreparer struct {
	reader                  EvidenceCreationReader
	authorizer              application.Authorizer
	objects                 EvidenceCreationPayloadValidator
	canonicalizer           Canonicalizer
	canonicalizationProfile string
	clock                   application.Clock
	ids                     application.IDGenerator
}

type preparedEvidence struct {
	authorizationScope string
	input              CreateEvidenceInput
	scope              EvidenceScope
	subjectRefs        []evidencedomain.SubjectRef
	item               evidencedomain.EvidenceItem
	at                 time.Time
}

func NewEvidenceCreationCommands(c EvidenceCreationCommandConfig) (*EvidenceCreationCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Authorizer == nil || c.Payloads == nil || c.Canonicalizer == nil || c.Clock == nil || c.IDs == nil || strings.TrimSpace(c.CanonicalizationProfile) == "" {
		return nil, ErrValidation
	}
	return &EvidenceCreationCommands{
		preparer:     evidencePreparer{reader: c.Reader, authorizer: c.Authorizer, objects: c.Payloads, canonicalizer: c.Canonicalizer, canonicalizationProfile: strings.TrimSpace(c.CanonicalizationProfile), clock: c.Clock, ids: c.IDs},
		transactions: c.Transactions,
	}, nil
}

func (c *EvidenceCreationCommands) CreateEvidence(ctx context.Context, actor identitydomain.Actor, input CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := c.preparer.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	var err error
	input, err = NormalizeGenericEvidenceCreation(input)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	prepared, err := c.preparer.prepareEvidenceForScope(ctx, actor, ScopeEvidenceWrite, input)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	err = c.transactions.ExecuteEvidenceCreation(ctx, func(ctx context.Context, tx EvidenceCreationTransaction) error {
		return c.preparer.persistPreparedEvidence(ctx, tx, actor, &prepared)
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return cloneEvidence(prepared.item), nil
}

func (s *evidencePreparer) prepareEvidenceForScope(ctx context.Context, actor identitydomain.Actor, authorizationScope string, input CreateEvidenceInput) (preparedEvidence, error) {
	if err := contextError(ctx); err != nil {
		return preparedEvidence{}, err
	}
	if authorizationScope != ScopeEvidenceWrite && authorizationScope != ScopeSecurityWrite {
		return preparedEvidence{}, ErrValidation
	}
	if err := s.authorize(ctx, actor, authorizationScope, application.ResourceReferences{}, true); err != nil {
		return preparedEvidence{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.BuildID = strings.TrimSpace(input.BuildID)
	input.DeploymentID = strings.TrimSpace(input.DeploymentID)
	input.Type = strings.TrimSpace(input.Type)
	input.Subtype = strings.TrimSpace(input.Subtype)
	input.Title = strings.TrimSpace(input.Title)
	input.PayloadHash = strings.TrimSpace(input.PayloadHash)
	input.PayloadRef = strings.TrimSpace(input.PayloadRef)
	input.PayloadMediaType = strings.TrimSpace(input.PayloadMediaType)
	subjectRefs, err := normalizeSubjectRefs(input.SubjectRefs)
	if err != nil {
		return preparedEvidence{}, err
	}
	input.SubjectRefs = subjectRefs
	// Deployment evidence is owned by the deployment command, which validates
	// deployment:write authority and persists the deployment/event back-reference
	// atomically. Generic evidence and parser callers must not opt into its
	// pending-reference exception by choosing reserved type/subtype values.
	if isDeploymentEvent(input.Type, input.Subtype) || input.Type == parserNormalizationType {
		return preparedEvidence{}, ErrValidation
	}
	if input.Type == "" || input.Title == "" || !validDigest(input.PayloadHash) || input.PayloadSize < 0 {
		return preparedEvidence{}, ErrValidation
	}
	// Reject unsupported or cyclic input before copying or committing it. The
	// HTTP decoder supplies JSON-shaped maps; parser adapters retain numeric
	// value types while the copy isolates nested maps and arrays.
	for _, value := range []map[string]any{input.SourceIdentity, input.Metadata} {
		if _, err := json.Marshal(value); err != nil {
			return preparedEvidence{}, ErrValidation
		}
	}
	if input.ObservedAt.IsZero() {
		input.ObservedAt = s.clock.Now()
	}
	if err := s.validatePayload(ctx, actor.TenantID, input); err != nil {
		return preparedEvidence{}, err
	}
	if actor.CollectorID != "" {
		input.CollectorID = actor.CollectorID
	}
	scope := EvidenceScope{
		ProductID: input.ProductID, ProjectID: input.ProjectID, ReleaseID: input.ReleaseID,
		BuildID: input.BuildID, DeploymentID: input.DeploymentID,
		AllowPendingDeployment: input.DeploymentID != "" && input.Type == "deployment" && input.Subtype == "event",
	}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return preparedEvidence{}, err
	}
	if err := s.authorize(ctx, actor, authorizationScope, resourceReferences(scope), false); err != nil {
		return preparedEvidence{}, err
	}
	if err := s.validateAndAuthorizeSubjectRefs(ctx, actor, authorizationScope, subjectRefs); err != nil {
		return preparedEvidence{}, err
	}
	input.SubjectRefs = withEvidenceOriginRefs(input.SubjectRefs, scope)
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	item := evidencedomain.EvidenceItem{
		ID: s.ids.NewID("ev"), TenantID: actor.TenantID, ProductID: input.ProductID, ProjectID: input.ProjectID,
		ReleaseID: input.ReleaseID, BuildID: input.BuildID, DeploymentID: input.DeploymentID,
		Type: input.Type, Subtype: input.Subtype, Title: input.Title, SourceSystem: nonEmpty(input.SourceSystem, "api"),
		SourceIdentity: cloneMap(input.SourceIdentity), CollectorID: strings.TrimSpace(input.CollectorID), UploadedBy: actor.KeyID,
		ObservedAt: input.ObservedAt.UTC().Truncate(time.Microsecond), EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion,
		PayloadRef: input.PayloadRef, PayloadHash: input.PayloadHash, PayloadMediaType: input.PayloadMediaType, PayloadSize: input.PayloadSize,
		Canonicalization: s.canonicalizationProfile, SubjectRefs: append([]evidencedomain.SubjectRef(nil), input.SubjectRefs...),
		TrustLevel: "L2", VerificationStatus: "pending", Tags: sortedStrings(input.Tags), Metadata: cloneMap(input.Metadata),
		Limitations: append([]string(nil), input.Limitations...), CreatedAt: now,
	}
	canonicalHash, err := s.canonicalizer.HashEvidence(ctx, item)
	if err != nil || !validDigest(canonicalHash) {
		if err != nil {
			return preparedEvidence{}, err
		}
		return preparedEvidence{}, ErrValidation
	}
	item.CanonicalHash = canonicalHash
	return preparedEvidence{authorizationScope: authorizationScope, input: input, scope: scope, subjectRefs: subjectRefs, item: item, at: now}, nil
}

func (s *evidencePreparer) persistPreparedEvidence(ctx context.Context, tx EvidenceCreationTransaction, actor identitydomain.Actor, prepared *preparedEvidence) error {
	if err := tx.ValidateScope(ctx, actor.TenantID, prepared.scope); err != nil {
		return err
	}
	if err := revalidateCreationSubjects(ctx, tx, actor, prepared.authorizationScope, prepared.subjectRefs); err != nil {
		return err
	}
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: prepared.authorizationScope, Resources: resourceReferences(prepared.scope)}); err != nil {
		return err
	}
	if prepared.input.StagedPayload.Status == PayloadStatusStaged {
		if err := tx.RecordStagedPayload(ctx, prepared.input.StagedPayload); err != nil {
			return err
		}
		if err := tx.EnqueueOutbox(ctx, application.OutboxEvent{
			ID: s.ids.NewID("job"), TenantID: actor.TenantID, Kind: "finalize_payload", SubjectType: "object_payload",
			SubjectID: prepared.input.StagedPayload.Digest, CreatedAt: prepared.at,
			Payload: map[string]any{"payload_digest": prepared.input.StagedPayload.Digest, "payload_lifecycle": PayloadLifecycleVersion},
		}); err != nil {
			return err
		}
	}
	receipt, err := tx.AppendAudit(ctx, s.auditEvent(actor, prepared.at, "evidence.created", prepared.item.ID, prepared.item.PayloadHash))
	if err != nil {
		return err
	}
	if !validDeploymentEvidenceID(receipt.ID) {
		return ErrConflict
	}
	prepared.item.ChainEntryID = receipt.ID
	return tx.InsertEvidence(ctx, prepared.item)
}

func (s *evidencePreparer) validatePayload(ctx context.Context, tenantID string, input CreateEvidenceInput) error {
	payload := input.StagedPayload
	if !payload.Present() {
		return nil
	}
	if err := s.objects.ValidateStagedPayload(ctx, payload); err != nil {
		return err
	}
	if payload.TenantID != tenantID || payload.Digest != input.PayloadHash || payload.Reference() != input.PayloadRef || payload.Size != input.PayloadSize || payload.MediaType != input.PayloadMediaType {
		return ErrValidation
	}
	if payload.Status != PayloadStatusStaged && payload.Status != PayloadStatusFinalized {
		return ErrValidation
	}
	return nil
}

func (s *evidencePreparer) authorize(ctx context.Context, actor identitydomain.Actor, scope string, resources application.ResourceReferences, scopeOnly bool) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources, ScopeOnly: scopeOnly})
}

func (s *evidencePreparer) validateAndAuthorizeArtifactReference(ctx context.Context, actor identitydomain.Actor, scope, artifactID, digest string) error {
	if artifactID == "" {
		return nil
	}
	if err := s.authorize(ctx, actor, scope, application.ResourceReferences{ArtifactID: artifactID}, false); err != nil {
		return err
	}
	return s.reader.ValidateArtifactReference(ctx, actor.TenantID, artifactID, digest)
}

func (s *evidencePreparer) validateAndAuthorizeSubjectRefs(ctx context.Context, actor identitydomain.Actor, scope string, refs []evidencedomain.SubjectRef) error {
	for _, ref := range refs {
		if ref.ID == "" {
			continue
		}
		if ref.Type == "artifact" {
			digest, _ := canonicalSupportedSubjectDigest(ref.Digest)
			if err := s.validateAndAuthorizeArtifactReference(ctx, actor, scope, ref.ID, digest); err != nil {
				return err
			}
			continue
		}
		referenceScope, resources, err := subjectReferenceScope(ref)
		if err != nil {
			continue
		}
		if err := s.authorize(ctx, actor, scope, resources, false); err != nil {
			return err
		}
		if err := s.reader.ValidateScope(ctx, actor.TenantID, referenceScope); err != nil {
			return err
		}
	}
	return nil
}

func (s *evidencePreparer) auditEvent(actor identitydomain.Actor, at time.Time, entryType, evidenceID, payloadHash string) application.AuditEvent {
	return application.AuditEvent{ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType, SubjectType: "evidence_item", SubjectID: evidenceID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC(), PayloadHash: payloadHash}
}

func revalidateCreationSubjects(ctx context.Context, tx EvidenceCreationTransaction, actor identitydomain.Actor, scope string, refs []evidencedomain.SubjectRef) error {
	for _, ref := range refs {
		if ref.ID == "" {
			continue
		}
		if ref.Type == "artifact" {
			if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: application.ResourceReferences{ArtifactID: ref.ID}}); err != nil {
				return err
			}
			digest, _ := canonicalSupportedSubjectDigest(ref.Digest)
			if err := tx.ValidateArtifactReference(ctx, actor.TenantID, ref.ID, digest); err != nil {
				return err
			}
			continue
		}
		referenceScope, resources, err := subjectReferenceScope(ref)
		if err != nil {
			continue
		}
		if err := tx.ValidateScope(ctx, actor.TenantID, referenceScope); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources}); err != nil {
			return err
		}
	}
	return nil
}

// These adapters are the legacy/local Service bridge only. Production creation
// binds the flat runner directly and must not expose the broad Transaction.
type evidenceCreationTransactions struct{ runner TransactionRunner }

func (r evidenceCreationTransactions) ExecuteEvidenceCreation(ctx context.Context, fn func(context.Context, EvidenceCreationTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error { return fn(ctx, evidenceCreationTransaction{tx}) })
}

type evidenceCreationTransaction struct{ tx Transaction }

func (t evidenceCreationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return t.tx.Authorize(ctx, a, r)
}
func (t evidenceCreationTransaction) ValidateScope(ctx context.Context, tenant string, s EvidenceScope) error {
	return t.tx.Evidence().ValidateScope(ctx, tenant, s)
}
func (t evidenceCreationTransaction) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return t.tx.Ingestion().ValidateArtifactReference(ctx, tenant, id, digest)
}
func (t evidenceCreationTransaction) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	return t.tx.Evidence().InsertEvidence(ctx, v)
}
func (t evidenceCreationTransaction) RecordStagedPayload(ctx context.Context, p StagedPayload) error {
	return t.tx.Payloads().RecordStagedPayload(ctx, p)
}
func (t evidenceCreationTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, e)
}
func (t evidenceCreationTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.tx.Outbox().EnqueueOutbox(ctx, e)
}
