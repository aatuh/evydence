package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxArtifactSignatureTextBytes    = 64 << 10
	MaxArtifactSignaturePayloadBytes = 20 << 20
)

type SignatureArtifact struct{ ID, TenantID, Digest string }

// SignaturePayload contains only verified staging metadata, never payload bytes.
type SignaturePayload struct {
	TenantID, Digest, MediaType, StagingKey, FinalKey string
	Size                                              int64
	CreatedAt, UpdatedAt                              time.Time
}
type SignaturePayloadStager interface {
	StageSignaturePayload(context.Context, string, string, string, []byte, time.Time) (SignaturePayload, error)
}
type ArtifactSignatureCreationReader interface {
	LockSignatureArtifact(context.Context, string, string) (SignatureArtifact, error)
	LockArtifactSignatureCreationScope(context.Context, string, string) (application.ResourceReferences, error)
}
type ArtifactSignatureTransaction interface {
	ArtifactSignatureCreationReader
	application.Authorizer
	application.AuditAppender
	application.OutboxEnqueuer
	RecordSignaturePayload(context.Context, SignaturePayload) error
	InsertArtifactSignature(context.Context, verificationdomain.ArtifactSignature) error
}
type ArtifactSignatureTransactions interface {
	ExecuteArtifactSignature(context.Context, func(context.Context, ArtifactSignatureTransaction) error) error
}
type ArtifactSignatureConfig struct {
	Transactions ArtifactSignatureTransactions
	Authorizer   application.Authorizer
	Objects      SignaturePayloadStager
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ArtifactSignatureCommands struct{ config ArtifactSignatureConfig }
type CreateArtifactSignatureInput struct {
	ArtifactID, Algorithm, KeyID, Signature string
	RawPayload                              []byte
	PayloadMediaType                        string
}

func NewArtifactSignatureCommands(c ArtifactSignatureConfig) (*ArtifactSignatureCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Objects == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &ArtifactSignatureCommands{c}, nil
}

func (s *ArtifactSignatureCommands) CreateArtifactSignature(ctx context.Context, a identitydomain.Actor, in CreateArtifactSignatureInput) (verificationdomain.ArtifactSignature, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	if err := validateSigningKeyActor(a); err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	request := application.AuthorizationRequest{Scope: "evidence:write", ScopeOnly: true}
	if err := s.config.Authorizer.Authorize(ctx, a, request); err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	var err error
	in, err = NormalizeArtifactSignatureInput(in)
	if err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	var result verificationdomain.ArtifactSignature
	err = s.config.Transactions.ExecuteArtifactSignature(ctx, func(ctx context.Context, tx ArtifactSignatureTransaction) error {
		if err := tx.Authorize(ctx, a, request); err != nil {
			return err
		}
		artifact, err := tx.LockSignatureArtifact(ctx, a.TenantID, in.ArtifactID)
		if err != nil {
			return err
		}
		if artifact.TenantID != a.TenantID || artifact.ID != in.ArtifactID {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "evidence:write", Resources: application.ResourceReferences{ArtifactID: artifact.ID}}); err != nil {
			return err
		}
		if !validRetentionText(artifact.Digest, 1024) {
			return ErrConflict
		}
		at := s.config.Clock.Now().UTC()
		v := verificationdomain.ArtifactSignature{ID: s.config.IDs.NewID("artsig"), TenantID: a.TenantID, ArtifactID: artifact.ID, SubjectDigest: artifact.Digest, Algorithm: in.Algorithm, KeyID: in.KeyID, Signature: in.Signature, VerificationStatus: "recorded", SchemaVersion: verificationdomain.ArtifactSignatureSchemaVersion, CreatedAt: at}
		if len(in.RawPayload) > 0 {
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256(in.RawPayload))
			p, err := s.config.Objects.StageSignaturePayload(ctx, a.TenantID, in.PayloadMediaType, digest, in.RawPayload, at)
			if err != nil {
				return err
			}
			if p.TenantID != a.TenantID || p.Digest != digest || p.MediaType != in.PayloadMediaType || p.Size != int64(len(in.RawPayload)) || p.CreatedAt != at || p.UpdatedAt.IsZero() || !validRetentionText(p.FinalKey, 4096) || !validRetentionText(p.StagingKey, 4096) {
				return ErrConflict
			}
			if err := tx.RecordSignaturePayload(ctx, p); err != nil {
				return err
			}
			job := application.OutboxEvent{ID: s.config.IDs.NewID("job"), TenantID: a.TenantID, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: digest, Payload: map[string]any{"payload_digest": digest, "payload_lifecycle": "object-payload.v1"}, CreatedAt: at}
			if err := tx.EnqueueOutbox(ctx, job); err != nil {
				return err
			}
			v.PayloadHash, v.PayloadRef = digest, "object://"+p.FinalKey
		}
		if err := tx.InsertArtifactSignature(ctx, v); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "artifact_signature.created", SubjectType: "artifact_signature", SubjectID: v.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), PayloadHash: artifact.Digest, OccurredAt: at}); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	return result, nil
}

// NormalizeArtifactSignatureInput bounds raw text before trimming. Raw payload
// bytes remain untouched; HTTP separately requires an opaque JSON object.
func NormalizeArtifactSignatureInput(in CreateArtifactSignatureInput) (CreateArtifactSignatureInput, error) {
	if !validRetentionText(in.ArtifactID, 1024) || !validRetentionText(in.Algorithm, MaxArtifactSignatureTextBytes) || !validRetentionText(in.Signature, MaxArtifactSignatureTextBytes) || !operationText(in.KeyID, 1024) || !operationText(in.PayloadMediaType, 4096) || len(in.RawPayload) > MaxArtifactSignaturePayloadBytes {
		return in, ErrValidation
	}
	in.ArtifactID, in.Algorithm, in.KeyID, in.Signature = strings.TrimSpace(in.ArtifactID), strings.TrimSpace(in.Algorithm), strings.TrimSpace(in.KeyID), strings.TrimSpace(in.Signature)
	in.PayloadMediaType = strings.TrimSpace(in.PayloadMediaType)
	if !validRetentionText(in.ArtifactID, 1024) || !validRetentionText(in.Algorithm, MaxArtifactSignatureTextBytes) || !validRetentionText(in.Signature, MaxArtifactSignatureTextBytes) || in.KeyID != "" && !validRetentionText(in.KeyID, 1024) || len(in.RawPayload) > MaxArtifactSignaturePayloadBytes {
		return in, ErrValidation
	}
	if len(in.RawPayload) > 0 {
		if in.PayloadMediaType == "" {
			in.PayloadMediaType = "application/octet-stream"
		}
		if !validRetentionText(in.PayloadMediaType, 4096) || strings.ContainsAny(in.PayloadMediaType, "\r\n") {
			return in, ErrValidation
		}
		if _, _, err := mime.ParseMediaType(in.PayloadMediaType); err != nil {
			return in, ErrValidation
		}
	}
	return in, nil
}

// AuthorizeArtifactSignatureCreation resolves current ownership and grants
// before reservation/replay, without selecting a digest or staging a payload.
func (s *ArtifactSignatureCommands) AuthorizeArtifactSignatureCreation(ctx context.Context, a identitydomain.Actor, in CreateArtifactSignatureInput) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateSigningKeyActor(a); err != nil {
		return err
	}
	in, err := NormalizeArtifactSignatureInput(in)
	if err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "evidence:write", ScopeOnly: true}); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteArtifactSignature(ctx, func(ctx context.Context, tx ArtifactSignatureTransaction) error {
		refs, err := tx.LockArtifactSignatureCreationScope(ctx, a.TenantID, in.ArtifactID)
		if err != nil {
			return err
		}
		if refs != (application.ResourceReferences{ArtifactID: in.ArtifactID}) {
			return ErrNotFound
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "evidence:write", Resources: refs})
	})
}
