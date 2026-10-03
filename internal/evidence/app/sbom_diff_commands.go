package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Bounds match parser component/string limits; normalized projection bytes
// have a separate budget because JSON encoding can expand source text.
const SBOMDiffComponentLimit = 100000
const SBOMDiffProjectionByteLimit = 64 << 20
const SBOMDiffStringByteLimit = 1 << 20

type SBOMDiffSubject struct {
	ID, TenantID, EvidenceID string
	Resources                application.ResourceReferences
}
type SBOMDiffReader interface {
	ReadSBOMDiffSubject(context.Context, string, string) (SBOMDiffSubject, error)
	ReadSBOMDiffComponents(context.Context, string, string) ([]evidencedomain.SBOMComponent, error)
}
type SBOMDiffTransaction interface {
	SBOMDiffReader
	application.Authorizer
	application.AuditAppender
	InsertSBOMDiff(context.Context, evidencedomain.SBOMDiff) error
}
type SBOMDiffTransactionRunner interface {
	ExecuteSBOMDiff(context.Context, func(context.Context, SBOMDiffTransaction) error) error
}
type SBOMDiffCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions SBOMDiffTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SBOMDiffCommands struct{ config SBOMDiffCommandConfig }

func NewSBOMDiffCommands(c SBOMDiffCommandConfig) (*SBOMDiffCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SBOMDiffCommands{c}, nil
}
func validDiffText(v string, max int, required bool) bool {
	return len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0) && (!required || strings.TrimSpace(v) != "")
}
func (s *SBOMDiffCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateSBOMDiffInput) (CreateSBOMDiffInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, ScopeOnly: true}); err != nil {
		return in, err
	}
	if !validDiffText(a.TenantID, 1024, true) || !validDiffText(auditActorID(a), 1024, true) {
		return in, ErrValidation
	}
	for _, v := range []string{in.BaseSBOMID, in.TargetSBOMID, in.ReleaseID} {
		if !validDiffText(v, 1024, false) {
			return in, ErrValidation
		}
	}
	in.BaseSBOMID = strings.TrimSpace(in.BaseSBOMID)
	in.TargetSBOMID = strings.TrimSpace(in.TargetSBOMID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	if in.BaseSBOMID == "" || in.TargetSBOMID == "" || in.BaseSBOMID == in.TargetSBOMID {
		return in, ErrValidation
	}
	return in, nil
}
func authorizeSBOMDiff(ctx context.Context, tx SBOMDiffTransaction, a identitydomain.Actor, in CreateSBOMDiffInput) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, ScopeOnly: true}); err != nil {
		return err
	}
	var subjects [2]SBOMDiffSubject
	for i, id := range []string{in.BaseSBOMID, in.TargetSBOMID} {
		v, err := tx.ReadSBOMDiffSubject(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != a.TenantID || !validDiffText(v.EvidenceID, 1024, true) {
			return ErrNotFound
		}
		r := v.Resources
		if r != (application.ResourceReferences{ProductID: r.ProductID, ProjectID: r.ProjectID, ReleaseID: r.ReleaseID, ArtifactID: r.ArtifactID}) {
			return ErrNotFound
		}
		for _, coordinate := range []string{r.ProductID, r.ProjectID, r.ReleaseID, r.ArtifactID} {
			if !validDiffText(coordinate, 1024, false) || strings.TrimSpace(coordinate) != coordinate {
				return ErrNotFound
			}
		}
		if (r.ProjectID != "" || r.ReleaseID != "") && r.ProductID == "" {
			return ErrNotFound
		}
		parent := r
		parent.ArtifactID = ""
		if parent != (application.ResourceReferences{}) || r.ArtifactID == "" {
			if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, Resources: parent}); err != nil {
				return err
			}
		}
		if r.ArtifactID != "" {
			if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, Resources: application.ResourceReferences{ArtifactID: r.ArtifactID}}); err != nil {
				return err
			}
		}
		subjects[i] = v
	}
	if in.ReleaseID != "" && in.ReleaseID != subjects[0].Resources.ReleaseID && in.ReleaseID != subjects[1].Resources.ReleaseID {
		return ErrValidation
	}
	return nil
}

// Saved-response replay resolves current parents and grants, never components.
func (s *SBOMDiffCommands) AuthorizeCreateSBOMDiff(ctx context.Context, a identitydomain.Actor, in CreateSBOMDiffInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSBOMDiff(ctx, func(ctx context.Context, tx SBOMDiffTransaction) error { return authorizeSBOMDiff(ctx, tx, a, in) })
}
func validDiffComponents(v []evidencedomain.SBOMComponent) bool {
	if len(v) > SBOMDiffComponentLimit {
		return false
	}
	remaining := SBOMDiffProjectionByteLimit
	for _, c := range v {
		if !validDiffText(c.Name, SBOMDiffStringByteLimit, true) {
			return false
		}
		for _, text := range []string{c.Identity, c.Name, c.Version, c.PURL} {
			if !validDiffText(text, SBOMDiffStringByteLimit, false) || len(text) > remaining {
				return false
			}
			remaining -= len(text)
		}
	}
	return true
}
func (s *SBOMDiffCommands) CreateSBOMDiff(ctx context.Context, a identitydomain.Actor, in CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	var v evidencedomain.SBOMDiff
	err = s.config.Transactions.ExecuteSBOMDiff(ctx, func(ctx context.Context, tx SBOMDiffTransaction) error {
		if err := authorizeSBOMDiff(ctx, tx, a, in); err != nil {
			return err
		}
		base, err := tx.ReadSBOMDiffComponents(ctx, a.TenantID, in.BaseSBOMID)
		if err != nil {
			return err
		}
		target, err := tx.ReadSBOMDiffComponents(ctx, a.TenantID, in.TargetSBOMID)
		if err != nil {
			return err
		}
		if !validDiffComponents(base) || !validDiffComponents(target) {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		added, removed, unchanged := diffComponents(base, target)
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
			return ErrValidation
		}
		v = evidencedomain.SBOMDiff{ID: s.config.IDs.NewID("sdiff"), TenantID: a.TenantID, BaseSBOMID: in.BaseSBOMID, TargetSBOMID: in.TargetSBOMID, ReleaseID: in.ReleaseID, AddedComponents: added, RemovedComponents: removed, UnchangedCount: unchanged, SchemaVersion: evidencedomain.SBOMDiffSchemaVersion, CreatedAt: now}
		if !validDiffText(v.ID, 1024, true) {
			return ErrValidation
		}
		for i, components := range [][]evidencedomain.SBOMComponent{added, removed} {
			kind := "added"
			if i == 1 {
				kind = "removed"
			}
			for _, c := range components {
				id := s.config.IDs.NewID("depchg")
				if !validDiffText(id, 1024, true) {
					return ErrValidation
				}
				v.DependencyChanges = append(v.DependencyChanges, evidencedomain.DependencyChange{ID: id, TenantID: a.TenantID, SBOMDiffID: v.ID, ChangeType: kind, Component: c, SchemaVersion: evidencedomain.DependencyChangeSchemaVersion, CreatedAt: now})
			}
		}
		if err := tx.InsertSBOMDiff(ctx, v); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sbom.diffed", SubjectType: "sbom_diff", SubjectID: v.ID, ActorID: auditActorID(a), ActorType: auditActorType(a), OccurredAt: now}
		if !validDiffText(audit.ID, 1024, true) {
			return ErrValidation
		}
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	return cloneSBOMDiff(v), nil
}
