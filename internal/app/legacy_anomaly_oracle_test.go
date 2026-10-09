package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

// Historical declarations retained unchanged for package-local regressions.
// Native HTTP fixtures read transaction repositories, never these caches.
// These oracles are not supported-runtime or SQL durability evidence.

type AnomalyReportInput struct {
	SubjectType string
	SubjectID   string
}

func (l *Ledger) GenerateAnomalyReport(ctx context.Context, actor domain.Actor, in AnomalyReportInput) (domain.AnomalyReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.AnomalyReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.AnomalyReport{}, err
	}
	v, err := experimentalapp.NormalizeAnomalyInput(experimentalapp.AnomalyReportInput{SubjectType: in.SubjectType, SubjectID: in.SubjectID})
	if err != nil {
		return domain.AnomalyReport{}, fromExperimentalCommandError(err)
	}
	subjectType, subjectID := v.SubjectType, v.SubjectID
	l.mu.Lock()
	defer l.mu.Unlock()
	refs, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID)
	if err != nil {
		return domain.AnomalyReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, refs); err != nil {
		return domain.AnomalyReport{}, err
	}
	var facts experimentalapp.AnomalyReleaseFacts
	if subjectType == "release" {
		facts = experimentalapp.AnomalyReleaseFacts{TenantID: actor.TenantID, ReleaseID: subjectID, HasPassedBuild: l.checkReleaseHasPassedBuildLocked(actor.TenantID, subjectID).Result == "passed", HasVerifiedBuildAttestation: l.checkReleaseHasBuildAttestationLocked(actor.TenantID, subjectID).Result == "passed", UnhandledCritical: len(l.unhandledCriticalFindingsLocked(actor.TenantID, subjectID)) > 0}
	}
	report := anomalyReportFromContext(experimentalapp.BuildAnomalyReport(newID("ano"), actor.TenantID, v, l.now(), facts))
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertAnomalyReport(ctx, report); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(report.CreatedAt, actor.TenantID, "anomaly_report.created", "anomaly_report", report.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.AnomalyReport{}, err
		}
		l.anomalyReports[report.ID] = cloneLocalAnomalyReport(report)
		l.publishCommittedAuditEntryLocked(entry)
		return report, nil
	}
	l.anomalyReports[report.ID] = cloneLocalAnomalyReport(report)
	_, _ = l.appendChainLocked(actor.TenantID, "anomaly_report.created", "anomaly_report", report.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.AnomalyReport{}, err
	}
	return report, nil
}

func (l *Ledger) ensureFutureSubjectLocked(tenantID, subjectType, subjectID string) (resourceRefs, error) {
	switch subjectType {
	case "tenant":
		if subjectID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{}, nil
	case "product":
		product, ok := l.products[subjectID]
		if !ok || product.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProductID: product.ID}, nil
	case "release":
		release, ok := l.releases[subjectID]
		if !ok || release.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}, nil
	case "evidence":
		item, ok := l.evidence[subjectID]
		if !ok || item.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return refsForEvidence(item), nil
	case "build":
		build, ok := l.buildRuns[subjectID]
		if !ok || build.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProjectID: build.ProjectID, ReleaseID: build.ReleaseID}, nil
	case "customer_package":
		pkg, ok := l.customerPackages[subjectID]
		if !ok || pkg.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}, nil
	default:
		return resourceRefs{}, ErrValidation
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
