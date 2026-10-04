package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

var _ e.PublicTransparencyMetadataReader = futureExtensions{}

func (r futureExtensions) ReadPublicTransparencyTenant(ctx context.Context, tenant string) error {
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR KEY SHARE`, tenant)
}
func (r futureExtensions) ReadPublicTransparencyPublication(ctx context.Context, tenant, log, checkpoint string) (e.PublicTransparencyPublicationSource, error) {
	if err := r.ReadPublicTransparencyTenant(ctx, tenant); err != nil {
		return e.PublicTransparencyPublicationSource{}, err
	}
	var s e.PublicTransparencyPublicationSource
	// Primary-key joins bound this to one source. Do not select endpoint/key
	// metadata or leaf/signature arrays. CASE caps transfer of corrupt DB text.
	err := r.tx.QueryRow(ctx, `SELECT l.id,c.id,
CASE WHEN octet_length(b.id)<=1024 THEN b.id ELSE '' END,
CASE WHEN octet_length(b.root_hash)<=128 THEN b.root_hash ELSE '' END
FROM public_transparency_logs l JOIN transparency_checkpoints c ON c.tenant_id=l.tenant_id
JOIN merkle_batches b ON b.id=c.batch_id AND b.tenant_id=c.tenant_id
WHERE l.tenant_id=$1 AND l.id=$2 AND c.id=$3 FOR SHARE OF l,c,b`, tenant, log, checkpoint).Scan(&s.LogID, &s.CheckpointID, &s.BatchID, &s.RootHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return e.PublicTransparencyPublicationSource{}, app.ErrNotFound
	}
	if err != nil {
		return e.PublicTransparencyPublicationSource{}, fmt.Errorf("read public transparency publication coordinates: %w", err)
	}
	s.TenantID = tenant
	return s, nil
}
func (r futureExtensions) InsertFocusedPublicTransparencyLog(ctx context.Context, v d.PublicTransparencyLog) error {
	if err := r.ReadPublicTransparencyTenant(ctx, v.TenantID); err != nil {
		return err
	}
	return r.InsertPublicTransparencyLog(ctx, app.PublicTransparencyLogLegacyRecord(v))
}
func (r futureExtensions) InsertFocusedPublicTransparencyEntry(ctx context.Context, v d.PublicTransparencyLogEntry) error {
	if _, err := r.ReadPublicTransparencyPublication(ctx, v.TenantID, v.LogID, v.CheckpointID); err != nil {
		return err
	}
	return r.InsertPublicTransparencyLogEntry(ctx, app.PublicTransparencyPublicationLegacyRecord(v))
}
