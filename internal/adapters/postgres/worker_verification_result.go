package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Store) loadWorkerVerificationResult(ctx context.Context, tenantID, id, subjectType, subjectID string) (domain.VerificationResult, error) {
	var result domain.VerificationResult
	var checks, profile []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, subject_type, subject_id, result, checks,
		       assurance_profile, limitations, schema_version, verified_at
		FROM verification_results
		WHERE tenant_id = $1 AND id = $2 AND subject_type = $3 AND subject_id = $4`,
		tenantID, id, subjectType, subjectID).Scan(
		&result.ID, &result.TenantID, &result.SubjectType, &result.SubjectID,
		&result.Result, &checks, &profile, &result.Limitations,
		&result.SchemaVersion, &result.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.VerificationResult{}, app.ErrNotFound
	}
	if err != nil {
		return domain.VerificationResult{}, fmt.Errorf("load worker verification result: %w", err)
	}
	if err := decodeJSON(checks, &result.Checks); err != nil {
		return domain.VerificationResult{}, app.ErrConflict
	}
	if err := decodeJSON(profile, &result.Profile); err != nil {
		return domain.VerificationResult{}, app.ErrConflict
	}
	return result, nil
}
