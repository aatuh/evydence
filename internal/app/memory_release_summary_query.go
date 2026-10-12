package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ReleaseSecuritySummaryReader = memoryDecisionRepository{}

func (r memoryDecisionRepository) ReadReleaseSecuritySummarySnapshot(ctx context.Context, tenant, release string) (riskquery.ReleaseSecuritySummarySnapshot, error) {
	return r.ReadReleaseSecuritySummarySnapshotAt(ctx, tenant, release, time.Now().UTC())
}

// One locked test transaction view supplies the same selected report fields,
// scalar counts and bounded findings as the native SQL reader, never Ledger.
func (r memoryDecisionRepository) ReadReleaseSecuritySummarySnapshotAt(ctx context.Context, tenant, release string, at time.Time) (riskquery.ReleaseSecuritySummarySnapshot, error) {
	if ctx == nil || !memoryMembershipQueryText(tenant, 1024) || !memoryMembershipQueryText(release, 1024) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return riskquery.ReleaseSecuritySummarySnapshot{}, riskquery.ErrValidation
	}
	var out riskquery.ReleaseSecuritySummarySnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		coords, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		readiness, err := readMemoryReadinessSnapshot(ctx, s, tenant, release, at)
		if err != nil {
			return err
		}
		p, v := s.Products[coords.ProductID], s.Releases[release]
		for _, text := range []string{p.Name, p.Slug, v.Version, v.State} {
			if !memoryMembershipText(text, 1024) {
				return riskquery.ErrInvalidProjection
			}
		}
		out = riskquery.ReleaseSecuritySummarySnapshot{TenantID: tenant, Product: riskdomain.ReleaseSecurityProductSummary{ID: p.ID, Name: p.Name, Slug: p.Slug}, Release: riskdomain.ReleaseSecurityReleaseSummary{ID: v.ID, Version: v.Version, State: v.State}, Readiness: readiness, Counts: memoryEvidenceFlowCounts(s, tenant, release), OpenFindingsBySeverity: map[string]int{}, DecisionsByStatus: map[string]int{}}
		group := func(counts map[string]int, key string) error {
			if key == "" || !memoryMembershipText(key, 64) {
				return riskquery.ErrInvalidProjection
			}
			counts[key]++
			if len(counts) > 32 {
				return riskquery.ErrInvalidProjection
			}
			return nil
		}
		for _, scan := range s.VulnerabilityScans {
			if scan.TenantID != tenant || scan.ReleaseID != release {
				continue
			}
			for _, f := range scan.Findings {
				state, severity := strings.ToLower(f.State), strings.ToLower(f.Severity)
				if state != "" && state != "open" {
					continue
				}
				if severity == "" {
					severity = "unknown"
				}
				if err := group(out.OpenFindingsBySeverity, severity); err != nil {
					return err
				}
			}
		}
		for _, d := range s.Decisions {
			if d.TenantID == tenant && d.ReleaseID == release && d.SupersededBy == "" {
				if err := group(out.DecisionsByStatus, d.Status); err != nil {
					return err
				}
			}
		}
		facts, err := readMemoryReadinessFacts(ctx, s, tenant, coords.ProductID, release, at)
		if err != nil {
			return err
		}
		for scan, findings := range facts.scans {
			duplicates := map[string]int{}
			for _, f := range findings {
				duplicates[f.ID]++
			}
			for _, f := range findings {
				if err := ctx.Err(); err != nil {
					return err
				}
				severity, state := strings.ToLower(f.Severity), strings.ToLower(f.State)
				if severity != "critical" && severity != "high" || state != "" && state != "open" {
					continue
				}
				if memoryReleaseFindingHandled(s, tenant, release, scan, f, duplicates[f.ID], at, facts.scans) {
					continue
				}
				if len(out.MissingRequiredDecisions) >= riskquery.MaxSecuritySummaryFindings {
					return riskquery.ErrInvalidProjection
				}
				for _, text := range []string{f.ID, scan, f.Vulnerability, f.Component} {
					if !memoryMembershipText(text, 1024) {
						return riskquery.ErrInvalidProjection
					}
				}
				if state == "" {
					state = "open"
				}
				out.MissingRequiredDecisions = append(out.MissingRequiredDecisions, riskdomain.ReleaseSecurityMissingDecision{FindingID: f.ID, ScanID: scan, Vulnerability: f.Vulnerability, Component: f.Component, Severity: severity, State: state})
			}
		}
		sort.Slice(out.MissingRequiredDecisions, func(i, j int) bool {
			a, b := out.MissingRequiredDecisions[i], out.MissingRequiredDecisions[j]
			if a.FindingID == b.FindingID {
				return a.ScanID < b.ScanID
			}
			return a.FindingID < b.FindingID
		})
		for _, a := range s.Approvals {
			if a.TenantID == tenant && a.SubjectType == "release" && a.SubjectID == release {
				out.ApprovalSummary.Total++
				if a.Decision == "approved" {
					out.ApprovalSummary.Approved++
				}
			}
		}
		for _, x := range s.Exceptions {
			if x.TenantID != tenant || x.ReleaseID != release {
				continue
			}
			out.ExceptionSummary.Total++
			if !x.ExpiresAt.After(at) {
				out.ExceptionSummary.Expired++
			} else if x.Approved {
				out.ExceptionSummary.ApprovedUnexpired++
			} else {
				out.ExceptionSummary.Unapproved++
			}
		}
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = riskquery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = riskquery.ErrInvalidProjection
	}
	if err != nil {
		return riskquery.ReleaseSecuritySummarySnapshot{}, err
	}
	return out, nil
}

func memoryReleaseFindingHandled(s *MemoryUnitOfWorkSnapshot, tenant, release, scan string, f domain.VulnerabilityFinding, duplicates int, at time.Time, scans map[string][]domain.VulnerabilityFinding) bool {
	for id, d := range s.Decisions {
		if d.ID == id && d.TenantID == tenant && d.ReleaseID == release && d.ScanID == scan && d.FindingID == f.ID && d.Vulnerability == f.Vulnerability && d.Component == f.Component && d.SupersededBy == "" && duplicates == 1 && (d.Status == "fixed" || d.Status == "not_affected") {
			return true
		}
	}
	return memoryAnomalyException(s, tenant, release, f.ID, at, scans)
}
