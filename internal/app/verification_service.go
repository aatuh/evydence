package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) GenerateBackupManifest(ctx context.Context, actor domain.Actor) (domain.BackupManifest, error) {
	value, err := l.verificationCommands.GenerateBackupManifest(ctx, actor)
	return backupManifestFromVerificationContext(value), fromVerificationContextError(err)
}
