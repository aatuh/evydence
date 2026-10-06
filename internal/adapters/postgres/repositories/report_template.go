package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// GetCustomReportTemplate reads and share-locks only the tenant-owned
// definition. Preflight its total bytes before transferring stored text.
func (r packages) GetCustomReportTemplate(ctx context.Context, tenantID, id string) (domain.CustomReportTemplate, error) {
	var empty domain.CustomReportTemplate
	if ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var value domain.CustomReportTemplate
	var fields []byte
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT
		CASE WHEN size.bytes<=$3 THEN t.name ELSE '' END,
		CASE WHEN size.bytes<=$3 THEN t.version ELSE '' END,
		CASE WHEN size.bytes<=$3 THEN t.report_type ELSE '' END,
		CASE WHEN size.bytes<=$3 THEN array_to_json(t.allowed_fields) ELSE '[]'::json END,
		CASE WHEN size.bytes<=$3 THEN t.template ELSE '' END,
		CASE WHEN size.bytes<=$3 THEN t.schema_version ELSE '' END,
		t.created_at,size.bytes>$3
		FROM report_templates t CROSS JOIN LATERAL (
			SELECT octet_length(t.id)::bigint+octet_length(t.tenant_id)+octet_length(t.name)+octet_length(t.version)+octet_length(t.report_type)+octet_length(array_to_json(t.allowed_fields)::text)+octet_length(t.template)+octet_length(t.schema_version) AS bytes
		) size
		WHERE t.tenant_id=$1 AND t.id=$2 FOR SHARE OF t`, tenantID, id, packageapp.MaxStoredReportTemplateBytes).Scan(&value.Name, &value.Version, &value.ReportType, &fields, &value.Template, &value.SchemaVersion, &value.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read report template: %w", err)
	}
	if oversized || json.Unmarshal(fields, &value.AllowedFields) != nil || len(value.AllowedFields) == 0 || value.Name == "" || value.Version == "" || value.ReportType == "" || value.SchemaVersion == "" || value.CreatedAt.IsZero() {
		return empty, app.ErrConflict
	}
	for _, field := range value.AllowedFields {
		if strings.TrimSpace(field) == "" {
			return empty, app.ErrConflict
		}
	}
	value.ID, value.TenantID = id, tenantID
	value.CreatedAt = value.CreatedAt.UTC()
	return value, nil
}
