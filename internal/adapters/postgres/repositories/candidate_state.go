package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var _ releaseapp.CandidateStateReader = releaseCatalog{}

// ReadCandidateState locks one candidate and its tenant-owned parents after
// the projection fence. Oversized documents never cross the SQL boundary.
func (r releaseCatalog) ReadCandidateState(ctx context.Context, tenant, id string) (releaseapp.CandidateStateRow, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.CandidateStateRow{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.CandidateStateRow{}, err
	}
	var row releaseapp.CandidateStateRow
	v := &row.Candidate
	var state string
	var document []byte
	var promoted, rejected sql.NullTime
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(c.id,1025),left(c.tenant_id,1025),left(c.release_id,1025),left(p.id,1025),left(c.name,65537),left(c.state,33),left(c.snapshot_hash,129),left(c.schema_version,1025),c.revision,c.created_at,c.promoted_at,c.rejected_at,
 CASE WHEN octet_length(c.document::text)<=1048576 THEN c.document ELSE NULL::jsonb END,
 octet_length(c.id)>1024 OR octet_length(c.tenant_id)>1024 OR octet_length(c.release_id)>1024 OR octet_length(p.id)>1024 OR octet_length(c.name)>65536 OR octet_length(c.state)>32 OR octet_length(c.snapshot_hash)>128 OR octet_length(c.schema_version)>1024 OR octet_length(c.document::text)>1048576
 FROM release_candidates c JOIN releases r ON r.id=c.release_id AND r.tenant_id=c.tenant_id
 JOIN products p ON p.id=r.product_id AND p.tenant_id=c.tenant_id
 WHERE c.tenant_id=$1 AND c.id=$2 FOR UPDATE OF c FOR SHARE OF r,p`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ReleaseID, &row.ProductID, &v.Name, &state, &v.SnapshotHash, &v.SchemaVersion, &v.Revision, &v.CreatedAt, &promoted, &rejected, &document, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.CandidateStateRow{}, app.ErrNotFound
	}
	if err != nil {
		return releaseapp.CandidateStateRow{}, fmt.Errorf("read candidate transition state: %w", err)
	}
	if large || v.Revision < 1 || v.CreatedAt.IsZero() || v.Name == "" || v.SnapshotHash == "" || v.SchemaVersion == "" {
		return releaseapp.CandidateStateRow{}, app.ErrConflict
	}
	v.State, err = releasedomain.ParseReleaseCandidateState(state)
	if err != nil {
		return releaseapp.CandidateStateRow{}, app.ErrConflict
	}
	// Columns own identity/lifecycle; only snapshot references come from JSON.
	var refs *struct {
		BuildIDs    []string `json:"build_ids"`
		ArtifactIDs []string `json:"artifact_ids"`
		SBOMIDs     []string `json:"sbom_ids"`
		ScanIDs     []string `json:"scan_ids"`
		VEXIDs      []string `json:"vex_ids"`
		ContractIDs []string `json:"contract_ids"`
		BundleIDs   []string `json:"bundle_ids"`
	}
	if err := json.Unmarshal(document, &refs); err != nil || refs == nil {
		return releaseapp.CandidateStateRow{}, app.ErrConflict
	}
	v.BuildIDs, v.ArtifactIDs, v.SBOMIDs, v.ScanIDs, v.VEXIDs, v.ContractIDs, v.BundleIDs = refs.BuildIDs, refs.ArtifactIDs, refs.SBOMIDs, refs.ScanIDs, refs.VEXIDs, refs.ContractIDs, refs.BundleIDs
	v.CreatedAt = v.CreatedAt.UTC()
	if promoted.Valid {
		at := promoted.Time.UTC()
		v.PromotedAt = &at
	}
	if rejected.Valid {
		at := rejected.Time.UTC()
		v.RejectedAt = &at
	}
	return row, nil
}
