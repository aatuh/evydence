package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type DeploymentEventEvidenceInput struct {
	ProductID, ReleaseID, EnvironmentID, DeploymentID, Status string
	ArtifactIDs                                               []string
	ObservedAt, CreatedAt                                     time.Time
}
type DeploymentEventEvidenceRepository interface {
	InsertEvidence(context.Context, evidencedomain.EvidenceItem) error
}
type DeploymentEventEvidenceConfig struct {
	Repository    DeploymentEventEvidenceRepository
	Audit         application.AuditAppender
	Canonicalizer Canonicalizer
	Authorizer    application.Authorizer
	IDs           application.IDGenerator
}

// DeploymentEventEvidenceWriter implements only the fixed-shape ADR 0003
// capability inside the caller's transaction. It neither opens a separate
// transaction nor accepts arbitrary evidence mutations.
type DeploymentEventEvidenceWriter struct{ config DeploymentEventEvidenceConfig }

func NewDeploymentEventEvidenceWriter(c DeploymentEventEvidenceConfig) (*DeploymentEventEvidenceWriter, error) {
	if c.Repository == nil || c.Audit == nil || c.Canonicalizer == nil || c.Authorizer == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &DeploymentEventEvidenceWriter{c}, nil
}
func validDeploymentEvidenceID(v string) bool {
	return v != "" && len(v) <= 1024 && utf8.ValidString(v) && !strings.ContainsRune(v, 0) && v == strings.TrimSpace(v)
}
func (w *DeploymentEventEvidenceWriter) WriteDeploymentEventEvidence(ctx context.Context, a identitydomain.Actor, in DeploymentEventEvidenceInput) (string, error) {
	if ctx == nil {
		return "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for _, id := range []string{a.TenantID, in.ProductID, in.ReleaseID, in.EnvironmentID, in.DeploymentID} {
		if !validDeploymentEvidenceID(id) {
			return "", ErrValidation
		}
	}
	if in.ObservedAt.IsZero() || in.CreatedAt.IsZero() || len(in.ArtifactIDs) > 1024 {
		return "", ErrValidation
	}
	// Hash exactly the timestamp precision persisted by PostgreSQL. The
	// canonicalization profile and historical evidence are not changed.
	in.ObservedAt = in.ObservedAt.UTC().Truncate(time.Microsecond)
	in.CreatedAt = in.CreatedAt.UTC().Truncate(time.Microsecond)
	switch in.Status {
	case "started", "succeeded", "failed", "rolled_back":
	default:
		return "", ErrValidation
	}
	for i, id := range in.ArtifactIDs {
		if !validDeploymentEvidenceID(id) || i > 0 && in.ArtifactIDs[i-1] > id {
			return "", ErrValidation
		}
	}
	if err := w.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: in.ProductID, ReleaseID: in.ReleaseID, EnvironmentID: in.EnvironmentID}}); err != nil {
		return "", err
	}
	// This is a commitment to submitted metadata, not a runtime observation.
	sum := sha256.Sum256([]byte(in.DeploymentID + ":" + in.Status))
	refs := make([]evidencedomain.SubjectRef, 0, len(in.ArtifactIDs)+3)
	refs = append(refs, evidencedomain.SubjectRef{Type: "release", ID: in.ReleaseID})
	for _, id := range in.ArtifactIDs {
		refs = append(refs, evidencedomain.SubjectRef{Type: "artifact", ID: id})
	}
	refs = append(refs, evidencedomain.SubjectRef{Type: "product", ID: in.ProductID}, evidencedomain.SubjectRef{Type: "deployment", ID: in.DeploymentID})
	item := evidencedomain.EvidenceItem{ID: w.config.IDs.NewID("ev"), TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, DeploymentID: in.DeploymentID, Type: "deployment", Subtype: "event", Title: "Deployment event", SourceSystem: "api", UploadedBy: a.KeyID, ObservedAt: in.ObservedAt.UTC(), EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion, PayloadHash: "sha256:" + hex.EncodeToString(sum[:]), Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, SubjectRefs: refs, TrustLevel: "L2", VerificationStatus: "pending", Tags: []string{}, Metadata: map[string]any{"environment_id": in.EnvironmentID, "status": in.Status}, Limitations: []string{"Deployment evidence records the supplied deployment metadata; it does not prove runtime security or availability."}, CreatedAt: in.CreatedAt.UTC()}
	var err error
	item.CanonicalHash, err = w.config.Canonicalizer.HashEvidence(ctx, item)
	if err != nil {
		return "", err
	}
	receipt, err := w.config.Audit.AppendAudit(ctx, application.AuditEvent{ID: w.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: item.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: item.CreatedAt, PayloadHash: item.PayloadHash})
	if err != nil {
		return "", err
	}
	if !validDeploymentEvidenceID(receipt.ID) {
		return "", ErrConflict
	}
	item.ChainEntryID = receipt.ID
	if err := w.config.Repository.InsertEvidence(ctx, item); err != nil {
		return "", err
	}
	return item.ID, nil
}
