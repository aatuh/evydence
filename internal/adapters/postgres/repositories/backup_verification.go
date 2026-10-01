package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (r verification) ReadBackupVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.BackupVerificationSnapshot, error) {
	snapshot := verificationapp.BackupVerificationSnapshot{Subject: s}
	if s.Type != "backup_manifest" || s.Resources != (application.ResourceReferences{}) {
		return snapshot, app.ErrValidation
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, s.TenantID); err != nil {
		return snapshot, err
	}
	var checks []byte
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(state_hash,1025),octet_length(state_hash)>1024,
		CASE WHEN octet_length(consistency_checks::text)<=$3 AND
			CASE WHEN jsonb_typeof(consistency_checks)='array' THEN jsonb_array_length(consistency_checks)<=$4 ELSE false END
		THEN consistency_checks ELSE NULL END
		FROM backup_manifests WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.TenantID, s.ID, verificationapp.MaxBackupVerificationBytes, verificationapp.MaxBackupVerificationChecks).Scan(&snapshot.StateHash, &oversized, &checks)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, fmt.Errorf("read recorded backup verification facts: %w", err)
	}
	if oversized || len(checks) == 0 || len(checks)+len(snapshot.StateHash) > verificationapp.MaxBackupVerificationBytes {
		return snapshot, app.ErrConflict
	}
	var recorded []domain.VerifyCheck
	if err := json.Unmarshal(checks, &recorded); err != nil || recorded == nil || len(recorded) > verificationapp.MaxBackupVerificationChecks {
		return snapshot, app.ErrConflict
	}
	for _, check := range recorded {
		snapshot.Checks = append(snapshot.Checks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return snapshot, nil
}
