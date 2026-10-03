package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const MaxRecordedCheckpointTextBytes = 1024 * 1024

// TransparencyCheckpointSource is an owned batch coordinate and recorded root,
// not a verification result or proof of external publication.
type TransparencyCheckpointSource struct {
	TenantID, ID, RootHash string
}
type TransparencyCheckpointReader interface {
	ReadTransparencyCheckpointSource(context.Context, string, string) (TransparencyCheckpointSource, error)
}
type TransparencyCheckpointTransaction interface {
	TransparencyCheckpointReader
	application.Authorizer
	application.AuditAppender
	InsertTransparencyCheckpoint(context.Context, verificationdomain.TransparencyCheckpoint) error
}
type TransparencyCheckpointTransactions interface {
	ExecuteTransparencyCheckpoint(context.Context, func(context.Context, TransparencyCheckpointTransaction) error) error
}
type TransparencyCheckpointConfig struct {
	Transactions TransparencyCheckpointTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type TransparencyCheckpointCommands struct{ config TransparencyCheckpointConfig }

func NewTransparencyCheckpointCommands(c TransparencyCheckpointConfig) (*TransparencyCheckpointCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &TransparencyCheckpointCommands{config: c}, nil
}
func (s *TransparencyCheckpointCommands) CreateTransparencyCheckpoint(ctx context.Context, actor identitydomain.Actor, input CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	request := application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}
	if err := s.config.Authorizer.Authorize(ctx, actor, request); err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	input, err := normalizeTransparencyCheckpointInput(input)
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	var result verificationdomain.TransparencyCheckpoint
	err = s.config.Transactions.ExecuteTransparencyCheckpoint(ctx, func(ctx context.Context, tx TransparencyCheckpointTransaction) error {
		if err := tx.Authorize(ctx, actor, request); err != nil {
			return err
		}
		source, err := tx.ReadTransparencyCheckpointSource(ctx, actor.TenantID, input.BatchID)
		if err != nil {
			return err
		}
		checkpoint, err := recordedTransparencyCheckpoint(actor.TenantID, input, source, s.config.Hasher, s.config.Clock.Now().UTC(), s.config.IDs.NewID("tcp"))
		if err != nil {
			return err
		}
		if err := tx.InsertTransparencyCheckpoint(ctx, checkpoint); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "transparency_checkpoint.recorded", SubjectType: "transparency_checkpoint", SubjectID: checkpoint.ID, PayloadHash: checkpoint.TimestampHash, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: checkpoint.CreatedAt}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		result = checkpoint
		return nil
	})
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	return result, nil
}

func normalizeTransparencyCheckpointInput(input CreateTransparencyCheckpointInput) (CreateTransparencyCheckpointInput, error) {
	input.BatchID = strings.TrimSpace(input.BatchID)
	input.Provider = strings.TrimSpace(input.Provider)
	input.ExternalURL = strings.TrimSpace(input.ExternalURL)
	input.ExternalID = strings.TrimSpace(input.ExternalID)
	if !validSigningKeyText(input.BatchID) || len(input.BatchID) > 1024 || !validSigningKeyText(input.Provider) || input.ExternalURL == "" && input.ExternalID == "" {
		return input, ErrValidation
	}
	budget := MaxRecordedCheckpointTextBytes
	for _, value := range []string{input.BatchID, input.Provider, input.ExternalURL, input.ExternalID} {
		if value != "" && !validSigningKeyText(value) || len(value) > budget {
			return input, ErrValidation
		}
		budget -= len(value)
	}
	return input, nil
}
func recordedTransparencyCheckpoint(tenant string, input CreateTransparencyCheckpointInput, source TransparencyCheckpointSource, hasher CanonicalHasher, now time.Time, id string) (verificationdomain.TransparencyCheckpoint, error) {
	if source.ID != input.BatchID || source.TenantID != tenant || source.RootHash == "" {
		return verificationdomain.TransparencyCheckpoint{}, ErrNotFound
	}
	if !validSigningKeyText(source.RootHash) || len(source.RootHash) > 1024 {
		return verificationdomain.TransparencyCheckpoint{}, ErrConflict
	}
	hash, err := hasher.Hash(map[string]any{"batch_id": source.ID, "root_hash": source.RootHash, "provider": input.Provider, "external_url": input.ExternalURL, "external_id": input.ExternalID})
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	if !validSigningKeyText(hash) || len(hash) > 1024 {
		return verificationdomain.TransparencyCheckpoint{}, ErrValidation
	}
	return verificationdomain.TransparencyCheckpoint{ID: id, TenantID: tenant, BatchID: source.ID, Provider: input.Provider, ExternalURL: input.ExternalURL, ExternalID: input.ExternalID, TimestampHash: hash, State: "recorded", SchemaVersion: verificationdomain.TransparencyCheckpointVersion, CreatedAt: now}, nil
}
