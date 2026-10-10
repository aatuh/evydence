package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// The unchanged aggregate command bodies remain only for historical tests.
func (l *Ledger) VerifyMerkleBatch(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	return l.VerifySubject(ctx, actor, "merkle_batch", id)
}

type CreateMerkleBatchInput struct{ FromSequence, ToSequence int64 }
type CreateTransparencyCheckpointInput struct{ BatchID, Provider, ExternalURL, ExternalID string }

func (l *Ledger) CreateMerkleBatch(ctx context.Context, actor domain.Actor, in CreateMerkleBatchInput) (domain.MerkleBatch, error) {
	value, err := l.verificationCommands.CreateMerkleBatch(ctx, actor, verificationapp.CreateMerkleBatchInput{FromSequence: in.FromSequence, ToSequence: in.ToSequence})
	return merkleBatchFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) CreateTransparencyCheckpoint(ctx context.Context, actor domain.Actor, in CreateTransparencyCheckpointInput) (domain.TransparencyCheckpoint, error) {
	value, err := l.verificationCommands.CreateTransparencyCheckpoint(ctx, actor, verificationapp.CreateTransparencyCheckpointInput{
		BatchID: in.BatchID, Provider: in.Provider, ExternalURL: in.ExternalURL, ExternalID: in.ExternalID,
	})
	return transparencyCheckpointFromVerificationContext(value), fromVerificationContextError(err)
}
