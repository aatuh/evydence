package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ControlsReader = (*Store)(nil)

const maxStoredControlJSONBytes = 1 << 20

// PageFrameworks returns one bounded tenant-owned governance page.
func (s *Store) PageFrameworks(ctx context.Context, request riskquery.FrameworkPageRequest) (appquery.Result[riskdomain.ControlFramework], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return appquery.Result[riskdomain.ControlFramework]{}, riskquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	where, args, order, err := appendCreatedAtKeyset("f", []string{"f.tenant_id = $1"}, []any{request.TenantID}, request.Page, request.After)
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT f.id, f.tenant_id, f.name, f.slug, f.version,
		       f.description, f.status, f.schema_version, f.created_at
		FROM control_frameworks AS f
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, fmt.Errorf("page control frameworks: %w", err)
	}
	defer rows.Close()
	items := make([]riskdomain.ControlFramework, 0, request.Page.PageSize+1)
	for rows.Next() {
		var framework riskdomain.ControlFramework
		var description sql.NullString
		if err := rows.Scan(&framework.ID, &framework.TenantID, &framework.Name, &framework.Slug,
			&framework.Version, &description, &framework.Status, &framework.SchemaVersion,
			&framework.CreatedAt); err != nil {
			return appquery.Result[riskdomain.ControlFramework]{}, fmt.Errorf("scan control framework page: %w", err)
		}
		framework.Description = nullableSQLString(description)
		items = append(items, framework)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, fmt.Errorf("iterate control framework page: %w", err)
	}
	result := appquery.Result[riskdomain.ControlFramework]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}

// GetControl rejects a control whose framework is absent or belongs to
// another tenant. Both coordinates come from one database statement.
func (s *Store) GetControl(ctx context.Context, tenantID, id string) (riskdomain.SecurityControl, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return riskdomain.SecurityControl{}, riskquery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return riskdomain.SecurityControl{}, riskquery.ErrNotFound
	}
	var control riskdomain.SecurityControl
	var requirements, applicability, limitations []byte
	err := s.pool.QueryRow(ctx, `
		SELECT c.id, c.tenant_id, c.framework_id, c.code, c.title,
		       c.objective, c.evidence_requirements, c.applicability,
		       c.limitations, c.schema_version, c.created_at
		FROM security_controls AS c
		JOIN control_frameworks AS f ON f.id = c.framework_id AND f.tenant_id = c.tenant_id
		WHERE c.tenant_id = $1 AND c.id = $2`, tenantID, id).Scan(
		&control.ID, &control.TenantID, &control.FrameworkID, &control.Code,
		&control.Title, &control.Objective, &requirements, &applicability,
		&limitations, &control.SchemaVersion, &control.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskdomain.SecurityControl{}, riskquery.ErrNotFound
	}
	if err != nil {
		return riskdomain.SecurityControl{}, fmt.Errorf("get security control: %w", err)
	}
	if len(requirements) > maxStoredControlJSONBytes || len(applicability) > maxStoredControlJSONBytes || len(limitations) > maxStoredControlJSONBytes {
		return riskdomain.SecurityControl{}, riskquery.ErrInvalidProjection
	}
	var storedRequirements []struct {
		Type          string `json:"type"`
		FreshnessDays int    `json:"freshness_days"`
		Required      bool   `json:"required"`
	}
	if err := json.Unmarshal(requirements, &storedRequirements); err != nil {
		return riskdomain.SecurityControl{}, riskquery.ErrInvalidProjection
	}
	control.EvidenceRequirements = make([]riskdomain.ControlEvidenceRequirement, 0, len(storedRequirements))
	for _, requirement := range storedRequirements {
		control.EvidenceRequirements = append(control.EvidenceRequirements, riskdomain.ControlEvidenceRequirement{
			Type: requirement.Type, FreshnessDays: requirement.FreshnessDays, Required: requirement.Required,
		})
	}
	if err := json.Unmarshal(applicability, &control.Applicability); err != nil {
		return riskdomain.SecurityControl{}, riskquery.ErrInvalidProjection
	}
	if err := json.Unmarshal(limitations, &control.Limitations); err != nil {
		return riskdomain.SecurityControl{}, riskquery.ErrInvalidProjection
	}
	return control, nil
}
