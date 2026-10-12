package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
)

var _ experimentalquery.MarketplaceCollectorReader = (*Store)(nil)

// PageMarketplaceCollectors applies tenant ownership and the keyset limit in
// PostgreSQL; the API never loads a tenant-wide Ledger projection for this page.
func (s *Store) PageMarketplaceCollectors(ctx context.Context, request experimentalquery.MarketplaceCollectorPageRequest) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	var empty appquery.Result[experimentaldomain.MarketplaceCollector]
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return empty, experimentalquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return empty, err
	}
	where, args, order, err := appendCreatedAtKeyset("c", []string{"c.tenant_id = $1"}, []any{request.TenantID}, request.Page, request.After)
	if err != nil {
		return empty, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT c.id, c.tenant_id, c.name, c.provider, c.version, c.publisher,
		       c.manifest_hash, c.signature_id, c.sbom_id, c.scan_id, c.state,
		       c.limitations, c.schema_version, c.created_at
		FROM marketplace_collectors AS c
		WHERE %s ORDER BY %s LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page marketplace collectors: %w", err)
	}
	defer rows.Close()
	items := make([]experimentaldomain.MarketplaceCollector, 0, request.Page.PageSize+1)
	for rows.Next() {
		var item experimentaldomain.MarketplaceCollector
		var signatureID, sbomID, scanID sql.NullString
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider,
			&item.Version, &item.Publisher, &item.ManifestHash,
			&signatureID, &sbomID, &scanID, &item.State, &item.Limitations,
			&item.SchemaVersion, &item.CreatedAt); err != nil {
			return empty, fmt.Errorf("scan marketplace collector page: %w", err)
		}
		item.SignatureID, item.SBOMID, item.ScanID = nullableSQLString(signatureID), nullableSQLString(sbomID), nullableSQLString(scanID)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("iterate marketplace collector page: %w", err)
	}
	result := appquery.Result[experimentaldomain.MarketplaceCollector]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}

// GetMarketplaceCollectorPoint resolves each reference against the collector's
// tenant in the same statement. Foreign references remain invalid, not proof.
func (s *Store) GetMarketplaceCollectorPoint(ctx context.Context, tenantID, id string) (experimentalquery.MarketplaceCollectorPoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return experimentalquery.MarketplaceCollectorPoint{}, experimentalquery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return experimentalquery.MarketplaceCollectorPoint{}, experimentalquery.ErrNotFound
	}
	var point experimentalquery.MarketplaceCollectorPoint
	var signatureID, sbomID, scanID sql.NullString
	collector := &point.Collector
	err := s.pool.QueryRow(ctx, `
		SELECT c.id, c.tenant_id, c.name, c.provider, c.version, c.publisher,
		       c.manifest_hash, c.signature_id, c.sbom_id, c.scan_id, c.state,
		       c.limitations, c.schema_version, c.created_at,
		       EXISTS (SELECT 1 FROM signatures AS sig
		               JOIN signing_keys AS k ON k.id = sig.key_id AND k.tenant_id = sig.tenant_id
		               WHERE sig.id = c.signature_id AND sig.tenant_id = c.tenant_id),
		       EXISTS (SELECT 1 FROM sboms AS sbom
		               JOIN evidence_items AS e ON e.id = sbom.evidence_id AND e.tenant_id = sbom.tenant_id
		               WHERE sbom.id = c.sbom_id AND sbom.tenant_id = c.tenant_id),
		       EXISTS (SELECT 1 FROM vulnerability_scans AS scan
		               JOIN evidence_items AS e ON e.id = scan.evidence_id AND e.tenant_id = scan.tenant_id
		               WHERE scan.id = c.scan_id AND scan.tenant_id = c.tenant_id)
		FROM marketplace_collectors AS c
		WHERE c.tenant_id = $1 AND c.id = $2`, tenantID, id).Scan(
		&collector.ID, &collector.TenantID, &collector.Name, &collector.Provider,
		&collector.Version, &collector.Publisher, &collector.ManifestHash,
		&signatureID, &sbomID, &scanID, &collector.State, &collector.Limitations,
		&collector.SchemaVersion, &collector.CreatedAt,
		&point.SignatureFound, &point.SBOMFound, &point.ScanFound)
	if errors.Is(err, pgx.ErrNoRows) {
		return experimentalquery.MarketplaceCollectorPoint{}, experimentalquery.ErrNotFound
	}
	if err != nil {
		return experimentalquery.MarketplaceCollectorPoint{}, fmt.Errorf("get marketplace collector point: %w", err)
	}
	collector.SignatureID, collector.SBOMID, collector.ScanID = nullableSQLString(signatureID), nullableSQLString(sbomID), nullableSQLString(scanID)
	return point, nil
}
