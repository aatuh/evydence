package app

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

func fromExperimentalCommandError(err error) error {
	switch {
	case errors.Is(err, experimentalapp.ErrVerificationFailed):
		return ErrVerificationFailed
	case errors.Is(err, experimentalapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, experimentalapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, experimentalapp.ErrConflict):
		return ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return ErrForbidden
	default:
		return err
	}
}
func anomalyReportFromContext(v experimentaldomain.AnomalyReport) domain.AnomalyReport {
	signals := make([]domain.AnomalySignal, len(v.Signals))
	for i, s := range v.Signals {
		signals[i] = domain.AnomalySignal{Name: s.Name, Severity: s.Severity, Detail: s.Detail}
	}
	return domain.AnomalyReport{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Result: v.Result, Signals: signals, Assumptions: append([]string(nil), v.Assumptions...), Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func cloneLocalAnomalyReport(v domain.AnomalyReport) domain.AnomalyReport {
	v.Signals = append([]domain.AnomalySignal{}, v.Signals...)
	v.Assumptions = append([]string(nil), v.Assumptions...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func (l *Ledger) AuthorizeGenerateAnomalyReport(ctx context.Context, a domain.Actor, in AnomalyReportInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeReportRead); err != nil {
		return err
	}
	v, err := experimentalapp.NormalizeAnomalyInput(experimentalapp.AnomalyReportInput{SubjectType: in.SubjectType, SubjectID: in.SubjectID})
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	refs, err := l.ensureFutureSubjectLocked(a.TenantID, v.SubjectType, v.SubjectID)
	if err != nil {
		return err
	}
	return l.authorizeResourceLocked(a, ScopeReportRead, refs)
}
