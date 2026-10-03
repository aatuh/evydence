package app

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const MaxEvidenceVerificationOrigins = 4096
const MaxEvidenceVerificationBytes = 8 << 20

type EvidenceVerificationSnapshot struct {
	Subject   SubjectReference
	Item      evidencedomain.EvidenceItem
	Lifecycle []evidencedomain.EvidenceLifecycleEvent
}
type EvidenceVerificationReader interface {
	ResolveEvidenceVerificationSubject(context.Context, string, string) (SubjectReference, error)
	ReadEvidenceVerification(context.Context, SubjectReference) (EvidenceVerificationSnapshot, error)
}
type EvidenceVerificationTransaction interface {
	EvidenceVerificationReader
	application.Authorizer
	verificationReceiptTransaction
}
type EvidenceVerificationTransactions interface {
	ExecuteEvidenceVerification(context.Context, func(context.Context, EvidenceVerificationTransaction) error) error
}
type EvidenceCanonicalHasher interface {
	HashEvidence(context.Context, evidencedomain.EvidenceItem) (string, error)
}
type EvidenceVerificationConfig struct {
	Transactions EvidenceVerificationTransactions
	Authorizer   application.Authorizer
	Hasher       EvidenceCanonicalHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type EvidenceVerificationCommands struct{ config EvidenceVerificationConfig }

func NewEvidenceVerificationCommands(config EvidenceVerificationConfig) (*EvidenceVerificationCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &EvidenceVerificationCommands{config}, nil
}
func (s *EvidenceVerificationCommands) VerifyEvidence(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	id = strings.TrimSpace(id)
	if !validSigningKeyText(id) || len(id) > 1024 {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	var result verificationdomain.VerificationResult
	err := s.config.Transactions.ExecuteEvidenceVerification(ctx, func(ctx context.Context, tx EvidenceVerificationTransaction) error {
		subject, err := tx.ResolveEvidenceVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "evidence_item", id) {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources, TenantWide: emptyResources(subject.Resources)}); err != nil {
			return err
		}
		snapshot, err := tx.ReadEvidenceVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject || snapshot.Item.TenantID != actor.TenantID || snapshot.Item.ID != id || len(snapshot.Lifecycle) > MaxEvidenceVerificationOrigins {
			return ErrConflict
		}
		inspection, err := InspectEvidenceCanonicalHash(ctx, snapshot, s.config.Hasher)
		if err != nil {
			return err
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, subject, inspection, s.config.Clock.Now().UTC(), s.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if verificationReturnsFailure(result.Result) {
		return cloneVerificationResult(result), ErrVerificationFailed
	}
	return cloneVerificationResult(result), nil
}
func InspectEvidenceCanonicalHash(ctx context.Context, snapshot EvidenceVerificationSnapshot, hasher EvidenceCanonicalHasher) (SubjectInspection, error) {
	if err := contextError(ctx); err != nil {
		return SubjectInspection{}, err
	}
	if hasher == nil {
		return SubjectInspection{}, ErrValidation
	}
	item, err := evidenceWithCanonicalOrigin(snapshot.Item, snapshot.Lifecycle)
	var hash string
	if err == nil {
		hash, err = hasher.HashEvidence(ctx, item)
	}
	if ctx.Err() != nil {
		return SubjectInspection{}, ctx.Err()
	}
	result := "passed"
	if err != nil || hash != snapshot.Item.CanonicalHash {
		result = "failed"
	}
	return SubjectInspection{Checks: []verificationdomain.VerifyCheck{{Name: "canonical_hash", Result: result}}, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileEvidenceCanonicalHash, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: []string{"canonical_hash"}, TrustMaterial: []string{snapshot.Item.Canonicalization}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "canonical evidence fields", PayloadDigest: snapshot.Item.CanonicalHash, Limitations: []string{"Canonical evidence hashing does not validate the origin or completeness of the uploaded payload."}})}, nil
}

// Lifecycle details retain their versioned JSON representation at this
// application boundary. Domain reconstruction operates on typed facts only.
type canonicalOriginDTO struct {
	ProductID           string `json:"product_id,omitempty"`
	ProjectID           string `json:"project_id,omitempty"`
	ReleaseID           string `json:"release_id,omitempty"`
	BuildID             string `json:"build_id,omitempty"`
	DeploymentID        string `json:"deployment_id,omitempty"`
	RelatedEvidenceRefs []struct {
		Type         string `json:"type"`
		ID           string `json:"id"`
		Relationship string `json:"relationship,omitempty"`
	} `json:"related_evidence_refs,omitempty"`
	Supersedes   string `json:"supersedes,omitempty"`
	SupersededBy string `json:"superseded_by,omitempty"`
}

func evidenceWithCanonicalOrigin(item evidencedomain.EvidenceItem, events []evidencedomain.EvidenceLifecycleEvent) (evidencedomain.EvidenceItem, error) {
	if item.Canonicalization != evidencedomain.LegacyEvidenceCanonicalizationProfileVersion {
		return item, nil
	}
	var origins []evidencedomain.CanonicalEvidenceOrigin
	for _, event := range events {
		if event.TenantID != item.TenantID || event.EvidenceID != item.ID || event.SchemaVersion != evidencedomain.EvidenceRelationshipLifecycleSchemaVersion {
			continue
		}
		raw, ok := event.Details[evidencedomain.LegacyCanonicalOriginDetailKey]
		if !ok {
			continue
		}
		body, err := json.Marshal(raw)
		if err != nil {
			return evidencedomain.EvidenceItem{}, err
		}
		var decoded canonicalOriginDTO
		if err := json.Unmarshal(body, &decoded); err != nil {
			return evidencedomain.EvidenceItem{}, err
		}
		origin := evidencedomain.CanonicalEvidenceOrigin{TenantID: event.TenantID, EvidenceID: event.EvidenceID, SchemaVersion: event.SchemaVersion, ProductID: decoded.ProductID, ProjectID: decoded.ProjectID, ReleaseID: decoded.ReleaseID, BuildID: decoded.BuildID, DeploymentID: decoded.DeploymentID, Supersedes: decoded.Supersedes, SupersededBy: decoded.SupersededBy}
		if decoded.RelatedEvidenceRefs != nil {
			origin.RelatedEvidenceRefs = make([]evidencedomain.EvidenceRef, 0, len(decoded.RelatedEvidenceRefs))
		}
		for _, ref := range decoded.RelatedEvidenceRefs {
			origin.RelatedEvidenceRefs = append(origin.RelatedEvidenceRefs, evidencedomain.EvidenceRef{Type: ref.Type, ID: ref.ID, Relationship: ref.Relationship})
		}
		origins = append(origins, origin)
	}
	return evidencedomain.EvidenceWithCanonicalOrigin(item, origins)
}
