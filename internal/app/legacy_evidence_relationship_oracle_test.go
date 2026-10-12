package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// Historical aggregate behavior is retained only for characterization tests.
// Native handlers and HTTP fixtures use focused, current-repository commands.
func (l *Ledger) AuthorizeSupersedeEvidence(ctx context.Context, a domain.Actor, id, replacement, reason string) error {
	if err := localRelationshipCaller(ctx, a); err != nil {
		return err
	}
	id, replacement, _, err := evidenceapp.NormalizeEvidenceSupersession(id, replacement, reason)
	if err != nil {
		return ErrValidation
	}
	return l.authorizeEvidenceRelationships(a, []string{id, replacement}, "", "")
}
func (l *Ledger) AuthorizeLinkEvidence(ctx context.Context, a domain.Actor, id, kind, target string) error {
	if err := localRelationshipCaller(ctx, a); err != nil {
		return err
	}
	id, kind, target, err := evidenceapp.NormalizeEvidenceLink(id, kind, target)
	if err != nil {
		return ErrValidation
	}
	return l.authorizeEvidenceRelationships(a, []string{id}, kind, target)
}
func (l *Ledger) AuthorizeLifecycleEvent(ctx context.Context, a domain.Actor, id string, in evidenceapp.RecordLifecycleInput) error {
	if err := localRelationshipCaller(ctx, a); err != nil {
		return err
	}
	id, in, err := evidenceapp.NormalizeEvidenceLifecycle(id, in)
	if err != nil {
		return ErrValidation
	}
	ids := []string{id}
	if in.ReplacementID != "" && in.ReplacementID != id {
		ids = append(ids, in.ReplacementID)
	}
	return l.authorizeEvidenceRelationships(a, ids, "", "")
}
func localRelationshipCaller(ctx context.Context, a domain.Actor) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceWrite); err != nil {
		return err
	}
	if a.TenantID == "" || !validPublicMembershipText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}
func (l *Ledger) authorizeEvidenceRelationships(a domain.Actor, ids []string, kind, target string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	for _, id := range ids {
		v, ok := l.evidence[id]
		if !ok || v.TenantID != a.TenantID {
			return ErrNotFound
		}
		for _, coordinate := range []string{v.ProductID, v.ProjectID, v.ReleaseID, v.BuildID, v.DeploymentID} {
			if !validPublicMembershipText(coordinate, 1024) || strings.TrimSpace(coordinate) != coordinate {
				return ErrConflict
			}
		}
		if err := validateLedgerEvidenceScopeLocked(l, a.TenantID, evidenceapp.EvidenceScope{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID}); err != nil {
			return err
		}
		if err := l.authorizeResourceLocked(a, ScopeEvidenceWrite, resourceRefs{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID}); err != nil {
			return err
		}
	}
	switch kind {
	case "product":
		_, err := l.authorizeProductReleaseLocked(a, ScopeEvidenceWrite, target, "")
		return err
	case "release":
		_, err := l.authorizeProductReleaseLocked(a, ScopeEvidenceWrite, "", target)
		return err
	default:
		return nil
	}
}

func (l *Ledger) SupersedeEvidence(ctx context.Context, actor domain.Actor, id, replacementID, reason string) (domain.EvidenceItem, error) {
	value, err := l.legacyEvidenceCommands().SupersedeEvidence(ctx, actor, id, replacementID, reason)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) LinkEvidence(ctx context.Context, actor domain.Actor, id, targetType, targetID string) (domain.EvidenceItem, error) {
	value, err := l.legacyEvidenceCommands().LinkEvidence(ctx, actor, id, targetType, targetID)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) RecordEvidenceLifecycleEvent(ctx context.Context, actor domain.Actor, evidenceID string, in RecordEvidenceLifecycleInput) (domain.EvidenceLifecycleEvent, error) {
	event, err := l.legacyEvidenceCommands().RecordLifecycleEvent(ctx, actor, evidenceID, evidenceapp.RecordLifecycleInput{
		Action: in.Action, Reason: in.Reason, Details: cloneMap(in.Details), ReplacementID: in.ReplacementID,
	})
	return lifecycleFromEvidenceContext(event), fromEvidenceContextError(err)
}
