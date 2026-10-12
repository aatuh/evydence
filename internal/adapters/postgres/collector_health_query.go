package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.CollectorHealthReader = (*Store)(nil)

// GetCollectorHealthPoint reads at most one collector and two releases in a
// single repeatable-read snapshot. All three lookups carry tenant ownership.
func (s *Store) GetCollectorHealthPoint(ctx context.Context, tenantID, id string) (integrationquery.CollectorHealthPoint, error) {
	var empty integrationquery.CollectorHealthPoint
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return empty, integrationquery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, integrationquery.ErrNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin collector health read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var point integrationquery.CollectorHealthPoint
	var status string
	var lastSeenAt sql.NullTime
	err = tx.QueryRow(ctx, `
		SELECT id,tenant_id,name,type,version,api_key_id,status,last_seen_at,schema_version,created_at
		FROM collectors WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(
		&point.Collector.ID, &point.Collector.TenantID, &point.Collector.Name,
		&point.Collector.Type, &point.Collector.Version, &point.Collector.APIKeyID,
		&status, &lastSeenAt, &point.Collector.SchemaVersion, &point.Collector.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, integrationquery.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read collector health subject: %w", err)
	}
	point.Collector.Status, err = integrationdomain.ParseCollectorStatus(status)
	if err != nil {
		return empty, integrationquery.ErrInvalidProjection
	}
	point.Collector.LastSeenAt = nullableSQLTime(lastSeenAt)
	// The report does not expose allowed scopes, so the point query never reads
	// the potentially large credential metadata value.
	latest, err := readCollectorHealthRelease(ctx, tx, tenantID, id, false)
	if err != nil {
		return empty, err
	}
	pinned, err := readCollectorHealthRelease(ctx, tx, tenantID, id, true)
	if err != nil {
		return empty, err
	}
	point.LatestRelease, point.PinnedRelease = latest, pinned
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit collector health read: %w", err)
	}
	return point, nil
}

func readCollectorHealthRelease(ctx context.Context, tx pgx.Tx, tenantID, collectorID string, pinnedOnly bool) (*integrationdomain.CollectorRelease, error) {
	statement := `
		SELECT id,tenant_id,collector_id,version,artifact_digest,signature_id,sbom_id,scan_id,
		       pinned,verification_status,health_status,limitations,schema_version,created_at
		FROM collector_releases
		WHERE tenant_id=$1 AND collector_id=$2`
	if pinnedOnly {
		statement += ` AND pinned=true`
	}
	statement += ` ORDER BY created_at DESC,id DESC LIMIT 1`
	var release integrationdomain.CollectorRelease
	var signatureID, sbomID, scanID sql.NullString
	err := tx.QueryRow(ctx, statement, tenantID, collectorID).Scan(
		&release.ID, &release.TenantID, &release.CollectorID, &release.Version,
		&release.ArtifactDigest, &signatureID, &sbomID, &scanID, &release.Pinned,
		&release.VerificationStatus, &release.HealthStatus, &release.Limitations,
		&release.SchemaVersion, &release.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read collector health release: %w", err)
	}
	release.SignatureID, release.SBOMID, release.ScanID = nullableSQLString(signatureID), nullableSQLString(sbomID), nullableSQLString(scanID)
	return &release, nil
}
