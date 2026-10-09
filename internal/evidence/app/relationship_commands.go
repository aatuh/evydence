package app

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type RelationshipReader interface {
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateLinkTarget(context.Context, string, string, string) error
	GetEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	ListRelationshipOrigins(context.Context, string, string) ([]evidencedomain.EvidenceLifecycleEvent, error)
}
type RelationshipRepository interface {
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateLinkTarget(context.Context, string, string, string) error
	GetEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	RecordSupersession(context.Context, evidencedomain.EvidenceItem, evidencedomain.EvidenceItem) error
	CompareAndSwapEvidenceLinks(context.Context, evidencedomain.EvidenceItem, evidencedomain.EvidenceItem) error
	AppendLifecycle(context.Context, evidencedomain.EvidenceLifecycleEvent) error
}
type RelationshipTransaction interface {
	RelationshipRepository
	application.Authorizer
	application.AuditAppender
}
type RelationshipTransactions interface {
	ExecuteEvidenceRelationships(context.Context, func(context.Context, RelationshipTransaction) error) error
}
type RelationshipCommandConfig struct {
	Reader                  RelationshipReader
	Transactions            RelationshipTransactions
	Authorizer              application.Authorizer
	Canonicalizer           Canonicalizer
	LifecycleSanitizer      LifecycleSanitizer
	CanonicalizationProfile string
	Clock                   application.Clock
	IDs                     application.IDGenerator
}
type RelationshipCommands struct {
	reader                  RelationshipReader
	transactions            RelationshipTransactions
	authorizer              application.Authorizer
	canonicalizer           Canonicalizer
	lifecycleSanitizer      LifecycleSanitizer
	canonicalizationProfile string
	clock                   application.Clock
	ids                     application.IDGenerator
}

func NewRelationshipCommands(c RelationshipCommandConfig) (*RelationshipCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Authorizer == nil || c.Canonicalizer == nil || c.LifecycleSanitizer == nil || c.Clock == nil || c.IDs == nil || strings.TrimSpace(c.CanonicalizationProfile) == "" {
		return nil, ErrValidation
	}
	return &RelationshipCommands{c.Reader, c.Transactions, c.Authorizer, c.Canonicalizer, c.LifecycleSanitizer, strings.TrimSpace(c.CanonicalizationProfile), c.Clock, c.IDs}, nil
}
func (s *RelationshipCommands) authorize(ctx context.Context, a identitydomain.Actor, scope string, refs application.ResourceReferences, only bool) error {
	return s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: scope, Resources: refs, ScopeOnly: only})
}
func (s *RelationshipCommands) auditEvent(a identitydomain.Actor, at time.Time, kind, id, hash string) application.AuditEvent {
	return application.AuditEvent{ID: s.ids.NewID("ace"), TenantID: a.TenantID, EntryType: kind, SubjectType: "evidence_item", SubjectID: id, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: at.UTC(), PayloadHash: hash}
}
func (s *RelationshipCommands) SupersedeEvidence(ctx context.Context, actor identitydomain.Actor, id, replacementID, reason string) (evidencedomain.EvidenceItem, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	var inputErr error
	id, replacementID, reason, inputErr = NormalizeEvidenceSupersession(id, replacementID, reason)
	if inputErr != nil {
		return evidencedomain.EvidenceItem{}, ErrValidation
	}
	item, err := s.reader.GetEvidence(ctx, actor.TenantID, id)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, id, item); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	replacement, err := s.reader.GetEvidence(ctx, actor.TenantID, replacementID)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, replacementID, replacement); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if !s.supportsMutableRelationships(item) || !s.supportsMutableRelationships(replacement) {
		return evidencedomain.EvidenceItem{}, ErrConflict
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, evidenceReferences(item), false); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, evidenceReferences(replacement), false); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	itemOrigin, err := s.relationshipCanonicalOrigin(ctx, actor.TenantID, item)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	replacementOrigin, err := s.relationshipCanonicalOrigin(ctx, actor.TenantID, replacement)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	now := s.clock.Now().UTC()
	safeReason, safeDetails, err := s.lifecycleSanitizer.SanitizeLifecycle(ctx, reason, map[string]any{
		"operation": "supersede", "replacement_evidence_id": replacementID,
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if strings.TrimSpace(safeReason) == "" {
		return evidencedomain.EvidenceItem{}, ErrValidation
	}
	safeDetails = cloneMap(safeDetails)
	if safeDetails == nil {
		safeDetails = map[string]any{}
	}
	if itemOrigin != nil {
		safeDetails[legacyCanonicalOriginDetail] = *itemOrigin
	}
	event := evidencedomain.EvidenceLifecycleEvent{
		ID: s.ids.NewID("elc"), TenantID: actor.TenantID, EvidenceID: id,
		Action: lifecycleState(evidencedomain.EvidenceLifecycleAmendmentValue), Reason: safeReason,
		Details: cloneMap(safeDetails), ReplacementID: replacementID, ActorID: auditActorID(actor),
		SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, CreatedAt: now,
	}
	var replacementEvent *evidencedomain.EvidenceLifecycleEvent
	if replacementOrigin != nil {
		replacementDetails := cloneMap(safeDetails)
		replacementDetails["role"] = "replacement"
		replacementDetails["original_evidence_id"] = id
		replacementDetails[legacyCanonicalOriginDetail] = *replacementOrigin
		value := evidencedomain.EvidenceLifecycleEvent{
			ID: s.ids.NewID("elc"), TenantID: actor.TenantID, EvidenceID: replacementID,
			Action: lifecycleState(evidencedomain.EvidenceLifecycleAmendmentValue), Reason: safeReason,
			Details: replacementDetails, ActorID: auditActorID(actor),
			SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, CreatedAt: now,
		}
		replacementEvent = &value
	}
	err = s.transactions.ExecuteEvidenceRelationships(ctx, func(ctx context.Context, tx RelationshipTransaction) error {
		current, err := tx.GetEvidence(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if err := validateReturnedEvidence(ctx, tx, actor.TenantID, id, current); err != nil {
			return err
		}
		currentReplacement, err := tx.GetEvidence(ctx, actor.TenantID, replacementID)
		if err != nil {
			return err
		}
		if err := validateReturnedEvidence(ctx, tx, actor.TenantID, replacementID, currentReplacement); err != nil {
			return err
		}
		if evidenceReferences(current) != evidenceReferences(item) || evidenceReferences(currentReplacement) != evidenceReferences(replacement) {
			return ErrConflict
		}
		for _, record := range []evidencedomain.EvidenceItem{current, currentReplacement} {
			if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: evidenceReferences(record)}); err != nil {
				return err
			}
		}
		if !s.supportsMutableRelationships(current) || !s.supportsMutableRelationships(currentReplacement) {
			return ErrConflict
		}
		if current.SupersededBy != "" || currentReplacement.Supersedes != "" {
			return ErrConflict
		}
		current.SupersededBy = currentReplacement.ID
		currentReplacement.Supersedes = current.ID
		if err := tx.RecordSupersession(ctx, current, currentReplacement); err != nil {
			return err
		}
		if err := tx.AppendLifecycle(ctx, event); err != nil {
			return err
		}
		if replacementEvent != nil {
			if err := tx.AppendLifecycle(ctx, *replacementEvent); err != nil {
				return err
			}
		}
		_, err = tx.AppendAudit(ctx, s.auditEvent(actor, now, "evidence.superseded", current.ID, current.PayloadHash))
		if err == nil {
			item = current
		}
		return err
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return cloneEvidence(item), nil
}

func (s *RelationshipCommands) LinkEvidence(ctx context.Context, actor identitydomain.Actor, id, targetType, targetID string) (evidencedomain.EvidenceItem, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	var inputErr error
	id, targetType, targetID, inputErr = NormalizeEvidenceLink(id, targetType, targetID)
	if inputErr != nil {
		return evidencedomain.EvidenceItem{}, ErrValidation
	}
	item, err := s.reader.GetEvidence(ctx, actor.TenantID, id)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, id, item); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if !s.supportsMutableRelationships(item) {
		return evidencedomain.EvidenceItem{}, ErrConflict
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, evidenceReferences(item), false); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := s.reader.ValidateLinkTarget(ctx, actor.TenantID, targetType, targetID); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	targetReferences := application.ResourceReferences{}
	if targetType == "release" {
		targetReferences.ReleaseID = targetID
	} else {
		targetReferences.ProductID = targetID
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, targetReferences, false); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	itemOrigin, err := s.relationshipCanonicalOrigin(ctx, actor.TenantID, item)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	now := s.clock.Now().UTC()
	safeReason, safeDetails, err := s.lifecycleSanitizer.SanitizeLifecycle(ctx, "linked evidence to "+targetType, map[string]any{
		"operation": "link", "target_type": targetType, "target_id": targetID,
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if strings.TrimSpace(safeReason) == "" {
		return evidencedomain.EvidenceItem{}, ErrValidation
	}
	safeDetails = cloneMap(safeDetails)
	if safeDetails == nil {
		safeDetails = map[string]any{}
	}
	if itemOrigin != nil {
		safeDetails[legacyCanonicalOriginDetail] = *itemOrigin
	}
	event := evidencedomain.EvidenceLifecycleEvent{
		ID: s.ids.NewID("elc"), TenantID: actor.TenantID, EvidenceID: id,
		Action: lifecycleState(evidencedomain.EvidenceLifecycleAmendmentValue), Reason: safeReason,
		Details: cloneMap(safeDetails), ActorID: auditActorID(actor),
		SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.ExecuteEvidenceRelationships(ctx, func(ctx context.Context, tx RelationshipTransaction) error {
		current, err := tx.GetEvidence(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if err := validateReturnedEvidence(ctx, tx, actor.TenantID, id, current); err != nil {
			return err
		}
		if evidenceReferences(current) != evidenceReferences(item) {
			return ErrConflict
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: evidenceReferences(current)}); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: targetReferences}); err != nil {
			return err
		}
		if !s.supportsMutableRelationships(current) {
			return ErrConflict
		}
		if err := tx.ValidateLinkTarget(ctx, actor.TenantID, targetType, targetID); err != nil {
			return err
		}
		expected := cloneEvidence(current)
		if targetType == "release" {
			current.ReleaseID = targetID
		} else {
			current.ProductID = targetID
		}
		current.RelatedEvidenceRefs = append(current.RelatedEvidenceRefs, evidencedomain.EvidenceRef{Type: targetType, ID: targetID, Relationship: "linked_to"})
		if err := tx.ValidateScope(ctx, actor.TenantID, evidenceScope(current)); err != nil {
			return err
		}
		if err := tx.CompareAndSwapEvidenceLinks(ctx, expected, current); err != nil {
			return err
		}
		if err := tx.AppendLifecycle(ctx, event); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, s.auditEvent(actor, now, "evidence.linked", current.ID, current.PayloadHash))
		if err == nil {
			item = current
		}
		return err
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return cloneEvidence(item), nil
}

type RecordLifecycleInput struct {
	Action        string
	Reason        string
	Details       map[string]any
	ReplacementID string
}

func (s *RelationshipCommands) RecordLifecycleEvent(ctx context.Context, actor identitydomain.Actor, evidenceID string, input RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	var inputErr error
	evidenceID, input, inputErr = NormalizeEvidenceLifecycle(evidenceID, input)
	if inputErr != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, ErrValidation
	}
	action, _ := evidencedomain.ParseEvidenceLifecycleState(input.Action)
	item, err := s.reader.GetEvidence(ctx, actor.TenantID, evidenceID)
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, evidenceID, item); err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, evidenceReferences(item), false); err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	var replacement evidencedomain.EvidenceItem
	if input.ReplacementID != "" {
		replacement, err = s.reader.GetEvidence(ctx, actor.TenantID, input.ReplacementID)
		if err != nil {
			return evidencedomain.EvidenceLifecycleEvent{}, err
		}
		if err := validateReturnedEvidence(ctx, s.reader, actor.TenantID, input.ReplacementID, replacement); err != nil {
			return evidencedomain.EvidenceLifecycleEvent{}, err
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceWrite, evidenceReferences(replacement), false); err != nil {
			return evidencedomain.EvidenceLifecycleEvent{}, err
		}
	}
	safeReason, safeDetails, err := s.lifecycleSanitizer.SanitizeLifecycle(ctx, input.Reason, cloneMap(input.Details))
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	now := s.clock.Now().UTC()
	event := evidencedomain.EvidenceLifecycleEvent{
		ID: s.ids.NewID("elc"), TenantID: actor.TenantID, EvidenceID: item.ID, Action: action,
		Reason: safeReason, Details: cloneMap(safeDetails), ReplacementID: input.ReplacementID,
		ActorID: auditActorID(actor), SchemaVersion: evidencedomain.EvidenceLifecycleSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.ExecuteEvidenceRelationships(ctx, func(ctx context.Context, tx RelationshipTransaction) error {
		current, err := tx.GetEvidence(ctx, actor.TenantID, item.ID)
		if err != nil {
			return err
		}
		if err := validateReturnedEvidence(ctx, tx, actor.TenantID, item.ID, current); err != nil {
			return err
		}
		if evidenceReferences(current) != evidenceReferences(item) {
			return ErrConflict
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: evidenceReferences(current)}); err != nil {
			return err
		}
		if input.ReplacementID != "" {
			currentReplacement, err := tx.GetEvidence(ctx, actor.TenantID, input.ReplacementID)
			if err != nil {
				return err
			}
			if err := validateReturnedEvidence(ctx, tx, actor.TenantID, input.ReplacementID, currentReplacement); err != nil {
				return err
			}
			if evidenceReferences(currentReplacement) != evidenceReferences(replacement) {
				return ErrConflict
			}
			if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: evidenceReferences(currentReplacement)}); err != nil {
				return err
			}
		}
		if err := tx.AppendLifecycle(ctx, event); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, "evidence."+action.String(), current.ID, current.PayloadHash)
		audit.ActorType = auditActorType(actor)
		audit.ActorID = auditActorID(actor)
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	return cloneLifecycleEvent(event), nil
}

func (s *RelationshipCommands) supportsMutableRelationships(item evidencedomain.EvidenceItem) bool {
	if workerOwnedEvidenceType(item.Type) {
		return false
	}
	return item.Canonicalization == s.canonicalizationProfile || item.Canonicalization == evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
}

func (s *RelationshipCommands) relationshipCanonicalOrigin(ctx context.Context, tenantID string, item evidencedomain.EvidenceItem) (*canonicalRelationshipOrigin, error) {
	if item.Canonicalization == s.canonicalizationProfile {
		return nil, nil
	}
	if item.Canonicalization != evidencedomain.LegacyEvidenceCanonicalizationProfileVersion {
		return nil, ErrConflict
	}
	origin := canonicalOriginFromEvidence(item)
	events, err := s.reader.ListRelationshipOrigins(ctx, tenantID, item.ID)
	if err != nil {
		return nil, err
	}
	var recorded *canonicalRelationshipOrigin
	for _, event := range events {
		if err := validateReturnedLifecycleEvent(tenantID, item.ID, event); err != nil {
			return nil, err
		}
		if event.SchemaVersion != evidencedomain.EvidenceRelationshipLifecycleSchemaVersion {
			continue
		}
		raw, ok := event.Details[legacyCanonicalOriginDetail]
		if !ok {
			continue
		}
		decoded, err := decodeCanonicalRelationshipOrigin(raw)
		if err != nil {
			return nil, ErrConflict
		}
		if recorded != nil && !reflect.DeepEqual(*recorded, decoded) {
			return nil, ErrConflict
		}
		recorded = &decoded
	}
	if recorded != nil {
		origin = *recorded
	}
	candidate := applyCanonicalRelationshipOrigin(item, origin)
	hash, err := s.canonicalizer.HashEvidence(ctx, candidate)
	if err != nil {
		return nil, err
	}
	if hash != item.CanonicalHash {
		return nil, ErrConflict
	}
	return &origin, nil
}
