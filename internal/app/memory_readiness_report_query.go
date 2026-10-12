package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.ReleaseReadinessReportReader = memoryPackageRepository{}

// One memory transaction view supplies canonical readiness facts and bounded
// report details. This test model never constructs Ledger and does not prove
// PostgreSQL JSON validation, transfer/work bounds, locks or durability.
func (r memoryPackageRepository) ReadReleaseReadinessReportSnapshot(ctx context.Context, tenant, release string, at time.Time) (packagequery.ReleaseReadinessReportSnapshot, error) {
	if ctx == nil || r.uow == nil || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return packagequery.ReleaseReadinessReportSnapshot{}, packagequery.ErrReleaseReadinessValidation
	}
	var out packagequery.ReleaseReadinessReportSnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		readiness, err := readMemoryReadinessSnapshot(ctx, s, tenant, release, at)
		if err != nil {
			return err
		}
		out.Readiness = readiness
		remaining := packagequery.MaxReleaseReadinessEntries - len(readiness.MissingCustomerStatementIDs) - len(readiness.MissingNotAffectedReasonIDs) - len(readiness.IncompleteExceptionIDs) - len(readiness.InvalidPackageOrProfileIDs)
		if remaining < 0 {
			return packagequery.ErrReleaseReadinessProjection
		}
		facts, err := readMemoryReadinessFacts(ctx, s, tenant, readiness.ProductID, release, at)
		if err != nil {
			return err
		}
		for scan, findings := range facts.scans {
			duplicates := map[string]int{}
			for _, finding := range findings {
				duplicates[finding.ID]++
			}
			for _, finding := range findings {
				if err := ctx.Err(); err != nil {
					return err
				}
				state := strings.ToLower(finding.State)
				if !strings.EqualFold(finding.Severity, "critical") || state != "" && state != "open" || memoryReleaseFindingHandled(s, tenant, release, scan, finding, duplicates[finding.ID], at, facts.scans) {
					continue
				}
				if remaining == 0 {
					return packagequery.ErrReleaseReadinessProjection
				}
				for _, value := range []string{finding.ID, scan, finding.Vulnerability, finding.Component} {
					if !memoryMembershipText(value, 1024) {
						return packagequery.ErrReleaseReadinessProjection
					}
				}
				remaining--
				out.BlockingFindings = append(out.BlockingFindings, packagedomain.BlockingFinding{FindingID: finding.ID, ScanID: scan, ReleaseID: release, Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: "critical", State: "open"})
			}
		}
		for id, x := range s.Exceptions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if x.ID != id || x.TenantID != tenant || x.ReleaseID != release || !x.Approved || !x.ExpiresAt.After(at) {
				continue
			}
			if remaining == 0 || !memoryMembershipText(x.Reason, 4096) {
				return packagequery.ErrReleaseReadinessProjection
			}
			for _, value := range []string{x.ID, x.FindingID, x.ControlID, x.Owner, x.ApprovedBy} {
				if !memoryMembershipText(value, 1024) {
					return packagequery.ErrReleaseReadinessProjection
				}
			}
			remaining--
			x.ApprovedAt = cloneTimePtr(x.ApprovedAt)
			out.AcceptedExceptions = append(out.AcceptedExceptions, packagedomain.AcceptedExceptionSnapshot(x))
		}
		for id, d := range s.Decisions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.ID == id && d.TenantID == tenant && d.ReleaseID == release && d.SupersededBy == "" {
				out.ActiveDecisionCount++
			}
		}
		for id, p := range s.CustomerPackages {
			if err := ctx.Err(); err != nil {
				return err
			}
			if p.ID == id && p.TenantID == tenant && p.ReleaseID == release && p.State == "generated" && p.ExpiresAt.After(at) {
				out.HasActiveCustomerPackage = true
				break
			}
		}
		sort.Slice(out.BlockingFindings, func(i, j int) bool {
			a, b := out.BlockingFindings[i], out.BlockingFindings[j]
			return a.FindingID < b.FindingID || a.FindingID == b.FindingID && a.ScanID < b.ScanID
		})
		sort.Slice(out.AcceptedExceptions, func(i, j int) bool { return out.AcceptedExceptions[i].ID < out.AcceptedExceptions[j].ID })
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = packagequery.ErrReleaseReadinessNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = packagequery.ErrReleaseReadinessProjection
	}
	if err != nil {
		return packagequery.ReleaseReadinessReportSnapshot{}, err
	}
	return out, nil
}
