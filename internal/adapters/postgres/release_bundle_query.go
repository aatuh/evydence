package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.ReleaseBundleReader = (*Store)(nil)

// GetReleaseBundlePoint reads one bundle with its current tenant-owned release
// and product in a single database snapshot. It never loads tenant-wide state.
func (s *Store) GetReleaseBundlePoint(ctx context.Context, tenantID, id string) (packagequery.ReleaseBundlePoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrReleaseBundleNotFound
	}
	var point packagequery.ReleaseBundlePoint
	var state string
	var manifest, signatureRefs []byte
	var publishedAt, revokedAt sql.NullTime
	bundle := &point.Bundle
	err := s.pool.QueryRow(ctx, `
		SELECT b.id, b.tenant_id, b.release_id, p.id, b.state,
		       b.manifest, b.manifest_hash, b.signature_refs,
		       b.created_at, b.published_at, b.revoked_at
		FROM release_bundles AS b
		JOIN releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id
		JOIN products AS p ON p.id = r.product_id AND p.tenant_id = b.tenant_id
		WHERE b.tenant_id = $1 AND b.id = $2`, tenantID, id).Scan(
		&bundle.ID, &bundle.TenantID, &bundle.ReleaseID, &point.ProductID,
		&state, &manifest, &bundle.ManifestHash, &signatureRefs,
		&bundle.CreatedAt, &publishedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrReleaseBundleNotFound
	}
	if err != nil {
		return packagequery.ReleaseBundlePoint{}, fmt.Errorf("get release bundle point: %w", err)
	}
	bundle.State, err = packagedomain.ParseBundleState(state)
	if err != nil {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrReleaseBundleProjection
	}
	bundle.Manifest, err = decodeReleaseBundleManifest(manifest)
	if err != nil {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrReleaseBundleProjection
	}
	if err := decodeJSON(signatureRefs, &bundle.SignatureRefs); err != nil || bundle.SignatureRefs == nil {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrReleaseBundleProjection
	}
	bundle.PublishedAt = nullableSQLTime(publishedAt)
	bundle.RevokedAt = nullableSQLTime(revokedAt)
	return point, nil
}

func decodeReleaseBundleManifest(raw []byte) (map[string]any, error) {
	var manifest map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil || manifest == nil {
		return nil, packagequery.ErrReleaseBundleProjection
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, packagequery.ErrReleaseBundleProjection
	}
	return manifest, nil
}
