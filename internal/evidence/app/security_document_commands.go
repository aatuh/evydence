package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

const SecurityDocumentFindingLimit = 100000

// Security document persistence cannot reach decision, policy, or incident
// repositories. Evidence and accepted document effects share one transaction.
type SecurityDocumentTransaction interface {
	EvidenceCreationTransaction
	InsertSecurityScan(context.Context, evidencedomain.SecurityScan) error
	InsertManualSecurityDocument(context.Context, evidencedomain.ManualSecurityDocument) error
}
type SecurityDocumentTransactionRunner interface {
	ExecuteSecurityDocument(context.Context, func(context.Context, SecurityDocumentTransaction) error) error
}
type SecurityDocumentCommandConfig struct {
	Authorizer              application.Authorizer
	Transactions            SecurityDocumentTransactionRunner
	Objects                 ObjectIngestion
	Canonicalizer           Canonicalizer
	CanonicalizationProfile string
	Clock                   application.Clock
	IDs                     application.IDGenerator
}
type SecurityDocumentCommands struct{ config SecurityDocumentCommandConfig }

func NewSecurityDocumentCommands(c SecurityDocumentCommandConfig) (*SecurityDocumentCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Objects == nil || c.Canonicalizer == nil || strings.TrimSpace(c.CanonicalizationProfile) == "" || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SecurityDocumentCommands{c}, nil
}
func (c *SecurityDocumentCommands) prepareActor(ctx context.Context, a identitydomain.Actor) error {
	if c == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeSecurityWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if !validDiffText(a.TenantID, 1024, true) || !validDiffText(auditActorID(a), 1024, true) {
		return ErrValidation
	}
	return nil
}
func (c *SecurityDocumentCommands) prepareScan(ctx context.Context, a identitydomain.Actor, in UploadSecurityScanInput) (UploadSecurityScanInput, error) {
	if err := c.prepareActor(ctx, a); err != nil {
		return in, err
	}
	for _, s := range []string{in.ProductID, in.ReleaseID, in.ArtifactID} {
		if !validDiffText(s, 1024, false) {
			return in, ErrValidation
		}
	}
	for _, s := range []string{in.Category, in.Format, in.Scanner, in.TargetRef} {
		if !validDiffText(s, 1<<20, false) {
			return in, ErrValidation
		}
	}
	in.ProductID, in.ReleaseID, in.ArtifactID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.ArtifactID)
	in.Category, in.Format, in.Scanner, in.TargetRef = strings.TrimSpace(in.Category), strings.TrimSpace(in.Format), strings.TrimSpace(in.Scanner), strings.TrimSpace(in.TargetRef)
	if !validSecurityScanCategory(in.Category) || in.Scanner == "" || in.TargetRef == "" || !validPayloadSize(int64(len(in.Raw)), EvidenceDocumentLimit) {
		return in, ErrValidation
	}
	return in, nil
}
func (c *SecurityDocumentCommands) prepareManual(ctx context.Context, a identitydomain.Actor, in UploadManualSecurityDocumentInput) (UploadManualSecurityDocumentInput, error) {
	if err := c.prepareActor(ctx, a); err != nil {
		return in, err
	}
	for _, s := range []string{in.ProductID, in.ReleaseID} {
		if !validDiffText(s, 1024, false) {
			return in, ErrValidation
		}
	}
	for _, s := range []string{in.DocumentType, in.Title, in.Sensitivity, in.MediaType} {
		if !validDiffText(s, 1<<20, false) {
			return in, ErrValidation
		}
	}
	in.ProductID, in.ReleaseID, in.DocumentType, in.Title, in.Sensitivity = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.DocumentType), strings.TrimSpace(in.Title), strings.TrimSpace(in.Sensitivity)
	in.MediaType = nonEmpty(in.MediaType, "application/octet-stream")
	if !validManualDocumentType(in.DocumentType) || in.Title == "" || !validSensitivity(in.Sensitivity) || !validPayloadSize(int64(len(in.Raw)), EvidenceDocumentLimit) {
		return in, ErrValidation
	}
	return in, nil
}
func authorizeSecurityDocument(ctx context.Context, tx SecurityDocumentTransaction, a identitydomain.Actor, scope EvidenceScope, artifact string) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeSecurityWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if err := tx.ValidateScope(ctx, a.TenantID, scope); err != nil {
		return err
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeSecurityWrite, Resources: resourceReferences(scope)}); err != nil {
		return err
	}
	if artifact != "" {
		if err := tx.ValidateArtifactReference(ctx, a.TenantID, artifact, ""); err != nil {
			return err
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeSecurityWrite, Resources: application.ResourceReferences{ArtifactID: artifact}})
	}
	return nil
}

// Replay guards check current ownership and grants without parsing or staging.
func (c *SecurityDocumentCommands) AuthorizeUploadSecurityScan(ctx context.Context, a identitydomain.Actor, in UploadSecurityScanInput) error {
	in, err := c.prepareScan(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteSecurityDocument(ctx, func(ctx context.Context, tx SecurityDocumentTransaction) error {
		return authorizeSecurityDocument(ctx, tx, a, EvidenceScope{ProductID: in.ProductID, ReleaseID: in.ReleaseID}, in.ArtifactID)
	})
}
func (c *SecurityDocumentCommands) AuthorizeUploadManualSecurityDocument(ctx context.Context, a identitydomain.Actor, in UploadManualSecurityDocumentInput) error {
	in, err := c.prepareManual(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteSecurityDocument(ctx, func(ctx context.Context, tx SecurityDocumentTransaction) error {
		return authorizeSecurityDocument(ctx, tx, a, EvidenceScope{ProductID: in.ProductID, ReleaseID: in.ReleaseID}, "")
	})
}

func (c *SecurityDocumentCommands) preparer(tx SecurityDocumentTransaction, now time.Time) evidencePreparer {
	return evidencePreparer{reader: tx, authorizer: tx, objects: c.config.Objects, canonicalizer: c.config.Canonicalizer, canonicalizationProfile: strings.TrimSpace(c.config.CanonicalizationProfile), clock: application.ClockFunc(func() time.Time { return now }), ids: c.config.IDs}
}
func (c *SecurityDocumentCommands) appendDocumentAudit(ctx context.Context, tx SecurityDocumentTransaction, a identitydomain.Actor, at time.Time, action, kind, id, digest string) error {
	e := application.AuditEvent{ID: c.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: action, SubjectType: kind, SubjectID: id, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: at, PayloadHash: digest}
	if !validDiffText(e.ID, 1024, true) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, e)
	return err
}
func validSecurityDocumentTime(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1 && at.Year() <= 9999
}

func validateSecurityScanJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrValidation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrValidation
	}
	limits := jsonbounds.DefaultLimits()
	limits.MaxArrayItems = SecurityDocumentFindingLimit
	limits.MaxStringBytes = 1 << 20
	if err := jsonbounds.Validate(raw, limits); err != nil {
		return ErrValidation
	}
	return nil
}
func validSecurityDocumentProjection(p parsedSecurityScan) bool {
	if p.FindingCount < 0 || p.FindingCount > SecurityDocumentFindingLimit || len(p.Summary) > SecurityDocumentFindingLimit || !validDiffText(p.Format, 1<<20, true) {
		return false
	}
	total, budget := 0, 8<<20
	for key, count := range p.Summary {
		if !validDiffText(key, 1<<20, true) || len(key) > budget || count <= 0 || count > p.FindingCount-total {
			return false
		}
		total += count
		budget -= len(key)
	}
	return total == p.FindingCount
}

func (c *SecurityDocumentCommands) UploadSecurityScan(ctx context.Context, a identitydomain.Actor, in UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	in, err := c.prepareScan(ctx, a, in)
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	var out evidencedomain.SecurityScan
	err = c.config.Transactions.ExecuteSecurityDocument(ctx, func(ctx context.Context, tx SecurityDocumentTransaction) error {
		if err := authorizeSecurityDocument(ctx, tx, a, EvidenceScope{ProductID: in.ProductID, ReleaseID: in.ReleaseID}, in.ArtifactID); err != nil {
			return err
		}
		if err := validateSecurityScanJSON(in.Raw); err != nil {
			return err
		}
		parsed, err := parseSecurityScan(in.Format, in.Raw)
		if err != nil {
			return err
		}
		if !validSecurityDocumentProjection(parsed) {
			return ErrValidation
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validSecurityDocumentTime(now) {
			return ErrValidation
		}
		digest := hashPayload(in.Raw)
		staged, err := c.config.Objects.StagePayload(ctx, a.TenantID, "application/json", digest, in.Raw)
		if err != nil {
			return err
		}
		p := c.preparer(tx, now)
		prepared, err := p.prepareEvidenceForScope(ctx, a, ScopeSecurityWrite, CreateEvidenceInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID, Type: in.Category, Subtype: parsed.Format, Title: in.Category + " scan", SourceSystem: in.Scanner, ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: digest, PayloadMediaType: "application/json", PayloadSize: int64(len(in.Raw)), StagedPayload: staged, SubjectRefs: subjectForArtifact(in.ArtifactID), Metadata: map[string]any{"scanner": in.Scanner, "target_ref": in.TargetRef, "finding_count": parsed.FindingCount}, Limitations: []string{"Scanner output is recorded as technical evidence; Evydence does not treat scanner findings as authoritative."}})
		if err != nil {
			return err
		}
		out = evidencedomain.SecurityScan{ID: c.config.IDs.NewID("secscan"), TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Category: in.Category, Format: parsed.Format, Scanner: in.Scanner, TargetRef: in.TargetRef, EvidenceID: prepared.item.ID, PayloadRef: staged.Reference(), PayloadHash: digest, FindingCount: parsed.FindingCount, Summary: cloneIntMap(parsed.Summary), Redacted: in.Category == "secret_scan", Quarantined: in.Category == "secret_scan" && parsed.FindingCount > 0, SchemaVersion: evidencedomain.SecurityScanSchemaVersion, CreatedAt: now}
		if !validDiffText(out.ID, 1024, true) || !validDiffText(out.EvidenceID, 1024, true) {
			return ErrValidation
		}
		if err := p.persistPreparedEvidence(ctx, tx, a, &prepared); err != nil {
			return err
		}
		if err := tx.InsertSecurityScan(ctx, out); err != nil {
			return err
		}
		return c.appendDocumentAudit(ctx, tx, a, now, "security_scan.uploaded", "security_scan", out.ID, digest)
	})
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	return cloneSecurityScan(out), nil
}

func (c *SecurityDocumentCommands) UploadManualSecurityDocument(ctx context.Context, a identitydomain.Actor, in UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error) {
	in, err := c.prepareManual(ctx, a, in)
	if err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	var out evidencedomain.ManualSecurityDocument
	err = c.config.Transactions.ExecuteSecurityDocument(ctx, func(ctx context.Context, tx SecurityDocumentTransaction) error {
		if err := authorizeSecurityDocument(ctx, tx, a, EvidenceScope{ProductID: in.ProductID, ReleaseID: in.ReleaseID}, ""); err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validSecurityDocumentTime(now) {
			return ErrValidation
		}
		digest := hashPayload(in.Raw)
		staged, err := c.config.Objects.StagePayload(ctx, a.TenantID, in.MediaType, digest, in.Raw)
		if err != nil {
			return err
		}
		p := c.preparer(tx, now)
		prepared, err := p.prepareEvidenceForScope(ctx, a, ScopeSecurityWrite, CreateEvidenceInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID, Type: in.DocumentType, Subtype: "manual", Title: in.Title, SourceSystem: "manual", ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: digest, PayloadMediaType: in.MediaType, PayloadSize: int64(len(in.Raw)), StagedPayload: staged, Metadata: map[string]any{"sensitivity": in.Sensitivity}, Limitations: []string{"Manual security evidence is lower default trust and requires human review."}})
		if err != nil {
			return err
		}
		out = evidencedomain.ManualSecurityDocument{ID: c.config.IDs.NewID("msd"), TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, DocumentType: in.DocumentType, Title: in.Title, Sensitivity: in.Sensitivity, EvidenceID: prepared.item.ID, PayloadRef: staged.Reference(), PayloadHash: digest, SchemaVersion: evidencedomain.ManualSecurityDocSchemaVersion, CreatedAt: now}
		if !validDiffText(out.ID, 1024, true) || !validDiffText(out.EvidenceID, 1024, true) {
			return ErrValidation
		}
		if err := p.persistPreparedEvidence(ctx, tx, a, &prepared); err != nil {
			return err
		}
		if err := tx.InsertManualSecurityDocument(ctx, out); err != nil {
			return err
		}
		return c.appendDocumentAudit(ctx, tx, a, now, "manual_security_document.uploaded", "manual_security_document", out.ID, digest)
	})
	if err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	return out, nil
}
