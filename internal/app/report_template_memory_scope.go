package app

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Selected typed fixture read; no aggregate cache, and no claim of PostgreSQL
// locks or pre-transfer bounds. Historical field order/duplicates are preserved.
func (r memoryPackageRepository) GetCustomReportTemplate(ctx context.Context, tenant, id string) (domain.CustomReportTemplate, error) {
	var out domain.CustomReportTemplate
	if ctx == nil || r.uow == nil || strings.TrimSpace(tenant) == "" || strings.TrimSpace(id) == "" {
		return out, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ReportTemplates[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if v.Name == "" || v.Version == "" || v.ReportType == "" || v.SchemaVersion == "" || v.CreatedAt.IsZero() || len(v.AllowedFields) == 0 {
			return ErrConflict
		}
		remaining := packageapp.MaxStoredReportTemplateBytes
		for _, text := range []string{v.ID, v.TenantID, v.Name, v.Version, v.ReportType, v.Template, v.SchemaVersion} {
			if !memoryGovernanceText(text, remaining) {
				return ErrConflict
			}
			remaining -= len(text)
		}
		// Bound before JSON allocation; the encoded array is charged below.
		fieldBudget := remaining
		if len(v.AllowedFields) > fieldBudget/3 {
			return ErrConflict
		}
		for _, field := range v.AllowedFields {
			if strings.TrimSpace(field) == "" || !memoryGovernanceText(field, fieldBudget) {
				return ErrConflict
			}
			fieldBudget -= len(field)
		}
		rawFields, err := json.Marshal(v.AllowedFields)
		if err != nil || len(rawFields) > remaining {
			return ErrConflict
		}
		v.AllowedFields = append([]string(nil), v.AllowedFields...)
		v.CreatedAt = v.CreatedAt.UTC()
		out = v
		return ctx.Err()
	})
	if err != nil {
		return domain.CustomReportTemplate{}, err
	}
	return out, nil
}

func (r memoryPackageRepository) LockReportTemplateTenant(ctx context.Context, tenant string) error {
	if ctx == nil || r.uow == nil {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error { return requireMemoryTenant(*state, tenant) })
}
func (r memoryPackageRepository) LockReportTemplateIdentity(ctx context.Context, tenant, id string) error {
	if ctx == nil || r.uow == nil {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, tenant); err != nil {
			return err
		}
		v, ok := state.ReportTemplates[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}
