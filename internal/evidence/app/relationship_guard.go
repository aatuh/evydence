package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type RelationshipScopeTransaction interface {
	LockRelationshipTenant(context.Context, string) error
	LockRelationshipEvidence(context.Context, string, string) (application.ResourceReferences, error)
	LockRelationshipTarget(context.Context, string, string, string) (application.ResourceReferences, error)
}

func NormalizeEvidenceSupersession(id, replacement, reason string) (string, string, string, error) {
	if !validGenericEvidenceText(id, 1024) || !validGenericEvidenceText(replacement, 1024) || !validGenericEvidenceText(reason, MaxGenericEvidenceTextBytes) {
		return "", "", "", ErrValidation
	}
	id, replacement, reason = strings.TrimSpace(id), strings.TrimSpace(replacement), strings.TrimSpace(reason)
	if id == "" || replacement == "" || id == replacement || reason == "" {
		return "", "", "", ErrValidation
	}
	return id, replacement, reason, nil
}
func NormalizeEvidenceLink(id, kind, target string) (string, string, string, error) {
	if !validGenericEvidenceText(id, 1024) || !validGenericEvidenceText(kind, 128) || !validGenericEvidenceText(target, 1024) {
		return "", "", "", ErrValidation
	}
	id, kind, target = strings.TrimSpace(id), strings.TrimSpace(kind), strings.TrimSpace(target)
	if id == "" || target == "" || kind != "product" && kind != "release" {
		return "", "", "", ErrValidation
	}
	return id, kind, target, nil
}
func NormalizeEvidenceLifecycle(id string, in RecordLifecycleInput) (string, RecordLifecycleInput, error) {
	if !validGenericEvidenceText(id, 1024) || !validGenericEvidenceText(in.ReplacementID, 1024) || !validGenericEvidenceText(in.Action, 128) || !validGenericEvidenceText(in.Reason, MaxGenericEvidenceTextBytes) {
		return "", RecordLifecycleInput{}, ErrValidation
	}
	if _, reserved := in.Details[legacyCanonicalOriginDetail]; reserved {
		return "", RecordLifecycleInput{}, ErrValidation
	}
	if err := validateGenericEvidenceJSON(in.Details); err != nil {
		return "", RecordLifecycleInput{}, err
	}
	id, in.ReplacementID, in.Reason = strings.TrimSpace(id), strings.TrimSpace(in.ReplacementID), strings.TrimSpace(in.Reason)
	action, err := evidencedomain.ParseEvidenceLifecycleState(in.Action)
	if id == "" || in.Reason == "" || err != nil {
		return "", RecordLifecycleInput{}, ErrValidation
	}
	in.Action = action.String()
	return id, in, nil
}

func (s *RelationshipCommands) AuthorizeSupersedeEvidence(ctx context.Context, a identitydomain.Actor, id, replacement, reason string) error {
	if err := s.relationshipContext(ctx); err != nil {
		return err
	}
	id, replacement, _, err := NormalizeEvidenceSupersession(id, replacement, reason)
	if err != nil {
		return err
	}
	return s.authorizeRelationship(ctx, a, []string{id, replacement}, "", "")
}
func (s *RelationshipCommands) AuthorizeLinkEvidence(ctx context.Context, a identitydomain.Actor, id, kind, target string) error {
	if err := s.relationshipContext(ctx); err != nil {
		return err
	}
	id, kind, target, err := NormalizeEvidenceLink(id, kind, target)
	if err != nil {
		return err
	}
	return s.authorizeRelationship(ctx, a, []string{id}, kind, target)
}
func (s *RelationshipCommands) AuthorizeLifecycleEvent(ctx context.Context, a identitydomain.Actor, id string, in RecordLifecycleInput) error {
	if err := s.relationshipContext(ctx); err != nil {
		return err
	}
	id, in, err := NormalizeEvidenceLifecycle(id, in)
	if err != nil {
		return err
	}
	ids := []string{id}
	if in.ReplacementID != "" && in.ReplacementID != id {
		ids = append(ids, in.ReplacementID)
	}
	return s.authorizeRelationship(ctx, a, ids, "", "")
}
func (s *RelationshipCommands) authorizeRelationship(ctx context.Context, a identitydomain.Actor, ids []string, kind, target string) error {
	if err := s.relationshipContext(ctx); err != nil {
		return err
	}
	if err := s.authorize(ctx, a, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return err
	}
	if a.TenantID == "" || !validGenericEvidenceText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	sort.Strings(ids)
	return s.transactions.ExecuteEvidenceRelationships(ctx, func(ctx context.Context, tx RelationshipTransaction) error {
		g, ok := tx.(RelationshipScopeTransaction)
		if !ok {
			return ErrValidation
		}
		if err := g.LockRelationshipTenant(ctx, a.TenantID); err != nil {
			return err
		}
		for _, id := range ids {
			refs, err := g.LockRelationshipEvidence(ctx, a.TenantID, id)
			if err != nil {
				return err
			}
			if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: refs}); err != nil {
				return err
			}
		}
		if kind != "" {
			refs, err := g.LockRelationshipTarget(ctx, a.TenantID, kind, target)
			if err != nil {
				return err
			}
			return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: refs})
		}
		return nil
	})
}

func (s *RelationshipCommands) relationshipContext(ctx context.Context) error {
	if s == nil {
		return ErrValidation
	}
	return contextError(ctx)
}
