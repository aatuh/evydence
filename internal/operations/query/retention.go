package query

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

// RetentionSnapshot contains only tenant-owned legal holds and overrides from
// one consistent database snapshot. It never includes provider retention state.
type RetentionSnapshot struct {
	LegalHolds         []operationsdomain.LegalHold
	RetentionOverrides []operationsdomain.RetentionOverride
}

type RetentionReader interface {
	ReadRetentionRecords(context.Context, string, string, string) (RetentionSnapshot, error)
}

type RetentionReport struct {
	reader RetentionReader
	now    func() time.Time
}

func NewRetentionReport(reader RetentionReader, now func() time.Time) (*RetentionReport, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &RetentionReport{reader: reader, now: now}, nil
}

// Report authorizes the tenant-wide inventory before loading retention rows.
func (s *RetentionReport) Report(ctx context.Context, actor identitydomain.Actor, scopeType, scopeID string) (operationsdomain.RetentionReport, error) {
	var empty operationsdomain.RetentionReport
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, "admin"); err != nil {
		return empty, err
	}
	snapshot, err := s.reader.ReadRetentionRecords(ctx, actor.TenantID, scopeType, scopeID)
	if err != nil {
		return empty, err
	}
	for _, hold := range snapshot.LegalHolds {
		if hold.ID == "" || hold.TenantID != actor.TenantID || scopeType != "" && (hold.ScopeType != scopeType || hold.ScopeID != scopeID) {
			return empty, ErrInvalidProjection
		}
	}
	for _, override := range snapshot.RetentionOverrides {
		if override.ID == "" || override.TenantID != actor.TenantID || scopeType != "" && (override.ScopeType != scopeType || override.ScopeID != scopeID) {
			return empty, ErrInvalidProjection
		}
	}
	return operationsdomain.RetentionReport{
		ReportType: "retention", ScopeType: scopeType, ScopeID: scopeID,
		LegalHolds: snapshot.LegalHolds, RetentionOverrides: snapshot.RetentionOverrides,
		Limitations: []string{"Retention reports describe Evydence records and do not replace external storage lifecycle verification."},
		GeneratedAt: s.now(),
	}, nil
}
