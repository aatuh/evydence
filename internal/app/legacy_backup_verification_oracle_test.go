package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// The unchanged historical facade is only an aggregate characterization oracle.
func (l *Ledger) VerifyBackupManifest(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	return l.VerifySubject(ctx, actor, "backup_manifest", id)
}
