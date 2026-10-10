package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// Unchanged historical behavior, retained only for legacy characterization tests.

type CreateSBOMDiffInput struct {
	BaseSBOMID   string
	TargetSBOMID string
	ReleaseID    string
}

type CreateContractDiffInput struct {
	BaseContractID   string
	TargetContractID string
	ReleaseID        string
}

func (l *Ledger) CreateSBOMDiff(ctx context.Context, actor domain.Actor, in CreateSBOMDiffInput) (domain.SBOMDiff, error) {
	value, err := l.legacyEvidenceCommands().CreateSBOMDiff(ctx, actor, evidenceapp.CreateSBOMDiffInput{
		BaseSBOMID: in.BaseSBOMID, TargetSBOMID: in.TargetSBOMID, ReleaseID: in.ReleaseID,
	})
	return sbomDiffFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) CreateContractDiff(ctx context.Context, actor domain.Actor, in CreateContractDiffInput) (domain.ContractDiff, error) {
	value, err := l.legacyEvidenceCommands().CreateContractDiff(ctx, actor, evidenceapp.CreateContractDiffInput{
		BaseContractID: in.BaseContractID, TargetContractID: in.TargetContractID, ReleaseID: in.ReleaseID,
	})
	return contractDiffFromEvidenceContext(value), fromEvidenceContextError(err)
}
