package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

var _ experimentalapp.AnomalyScopeReader = futureExtensions{}

func (r futureExtensions) ReadAnomalyScope(ctx context.Context, tenant, kind, id string) (experimentalapp.AnomalyScope, error) {
	s, err := r.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return experimentalapp.AnomalyScope{TenantID: s.TenantID, SubjectType: s.SubjectType, SubjectID: s.SubjectID, Resources: s.Resources}, err
}
func (r futureExtensions) InsertFocusedAnomalyReport(ctx context.Context, v experimentaldomain.AnomalyReport) error {
	if _, err := r.ReadAnomalyScope(ctx, v.TenantID, v.SubjectType, v.SubjectID); err != nil {
		return err
	}
	signals := make([]domain.AnomalySignal, len(v.Signals))
	for i, s := range v.Signals {
		signals[i] = domain.AnomalySignal{Name: s.Name, Severity: s.Severity, Detail: s.Detail}
	}
	return r.InsertAnomalyReport(ctx, domain.AnomalyReport{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Result: v.Result, Signals: signals, Assumptions: append([]string(nil), v.Assumptions...), Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}
