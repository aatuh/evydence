package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) VerifySubject(ctx context.Context, actor domain.Actor, subjectType, subjectID string) (domain.VerificationResult, error) {
	value, err := l.verificationCommands.VerifySubject(ctx, actor, subjectType, subjectID)
	return domain.VerificationResultFromContextModel(value), fromVerificationContextError(err)
}

func (l *Ledger) GenerateBackupManifest(ctx context.Context, actor domain.Actor) (domain.BackupManifest, error) {
	value, err := l.verificationCommands.GenerateBackupManifest(ctx, actor)
	return backupManifestFromVerificationContext(value), fromVerificationContextError(err)
}
