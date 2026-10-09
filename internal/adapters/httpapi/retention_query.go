package httpapi

import (
	"net/http"
	"net/url"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func retentionReportFilters(r *http.Request) (string, string, error) {
	if r == nil || r.URL == nil {
		return "", "", app.ErrValidation
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", "", app.ErrValidation
	}
	for key, entries := range values {
		if key != "scope_type" && key != "scope_id" || len(entries) != 1 {
			return "", "", app.ErrValidation
		}
	}
	return values.Get("scope_type"), values.Get("scope_id"), nil
}

func retentionReportFromQuery(report operationsdomain.RetentionReport) domain.RetentionReport {
	holds := make([]domain.LegalHold, 0, len(report.LegalHolds))
	for _, hold := range report.LegalHolds {
		holds = append(holds, domain.LegalHold{
			ID: hold.ID, TenantID: hold.TenantID, ScopeType: hold.ScopeType,
			ScopeID: hold.ScopeID, Reason: hold.Reason, Owner: hold.Owner,
			ReleasedAt: hold.ReleasedAt, SchemaVersion: hold.SchemaVersion,
			CreatedAt: hold.CreatedAt,
		})
	}
	overrides := make([]domain.RetentionOverride, 0, len(report.RetentionOverrides))
	for _, override := range report.RetentionOverrides {
		overrides = append(overrides, domain.RetentionOverride{
			ID: override.ID, TenantID: override.TenantID,
			ScopeType: override.ScopeType, ScopeID: override.ScopeID,
			RetentionUntil: override.RetentionUntil, Reason: override.Reason,
			Owner: override.Owner, SchemaVersion: override.SchemaVersion,
			CreatedAt: override.CreatedAt,
		})
	}
	return domain.RetentionReport{
		ReportType: report.ReportType, ScopeType: report.ScopeType,
		ScopeID: report.ScopeID, LegalHolds: holds,
		RetentionOverrides: overrides, Limitations: report.Limitations,
		GeneratedAt: report.GeneratedAt,
	}
}
