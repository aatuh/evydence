package query

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var (
	ErrControlCoverageValidation = errors.New("invalid control coverage report query")
	ErrControlCoverageNotFound   = errors.New("control coverage scope not found")
	ErrControlCoverageProjection = errors.New("invalid control coverage projection")
	ErrControlCoverageCapacity   = errors.New("control coverage report exceeds the bounded result size")
)

const MaxControlCoverageEntries = 4096

type ControlCoverageFilter struct {
	FrameworkID, ProductID, ReleaseID string
}

// ControlCoverageLink is a previously validated tenant-owned subject link.
// The reader resolves subject scope and its actual timestamp in the same
// committed database view; the report service never trusts link IDs alone.
type ControlCoverageLink struct {
	Link              riskdomain.ControlEvidence
	SubjectObservedAt time.Time
}

type ControlCoverageSnapshot struct {
	TenantID, FrameworkID, ScopeProductID, ScopeReleaseID string
	Controls                                              []riskdomain.SecurityControl
	Links                                                 []ControlCoverageLink
	Exceptions                                            []riskdomain.Exception
}

type ControlCoverageReader interface {
	ReadControlCoverageSnapshot(context.Context, string, string, string, string, time.Time) (ControlCoverageSnapshot, error)
}

type ControlCoverageReport struct {
	reader ControlCoverageReader
	now    func() time.Time
}

func NewControlCoverageReport(reader ControlCoverageReader, now func() time.Time) (*ControlCoverageReport, error) {
	if reader == nil || now == nil {
		return nil, ErrControlCoverageValidation
	}
	return &ControlCoverageReport{reader: reader, now: now}, nil
}

func (s *ControlCoverageReport) Coverage(ctx context.Context, actor identitydomain.Actor, filter ControlCoverageFilter) (packagedomain.ControlCoverageReport, error) {
	var empty packagedomain.ControlCoverageReport
	if s == nil || ctx == nil {
		return empty, ErrControlCoverageValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope("report:read") && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	filter.FrameworkID = strings.TrimSpace(filter.FrameworkID)
	filter.ProductID = strings.TrimSpace(filter.ProductID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	if filter.ProductID == "" && filter.ReleaseID == "" {
		if err := application.AuthorizeTenantWideScope(ctx, actor, "report:read"); err != nil {
			return empty, err
		}
	} else if filter.ProductID != "" && !releaseReportAllowed(actor, filter.ProductID, filter.ReleaseID) {
		return empty, application.ErrForbidden
	}
	now := s.now()
	snapshot, err := s.reader.ReadControlCoverageSnapshot(ctx, actor.TenantID, filter.FrameworkID, filter.ProductID, filter.ReleaseID, now)
	if err != nil {
		return empty, err
	}
	if snapshot.TenantID != actor.TenantID || snapshot.FrameworkID == "" ||
		filter.FrameworkID != "" && snapshot.FrameworkID != filter.FrameworkID ||
		snapshot.ScopeReleaseID != filter.ReleaseID ||
		filter.ProductID != "" && snapshot.ScopeProductID != filter.ProductID ||
		filter.ProductID == "" && filter.ReleaseID == "" && snapshot.ScopeProductID != "" ||
		filter.ReleaseID != "" && snapshot.ScopeProductID == "" {
		return empty, ErrControlCoverageNotFound
	}
	if !releaseReportAllowed(actor, snapshot.ScopeProductID, filter.ReleaseID) {
		return empty, application.ErrForbidden
	}
	if len(snapshot.Controls)+len(snapshot.Links)+len(snapshot.Exceptions) > MaxControlCoverageEntries {
		return empty, ErrControlCoverageCapacity
	}
	items, missing, exceptions, result, err := assembleControlCoverage(snapshot, filter.ReleaseID, now)
	if err != nil {
		return empty, err
	}
	return packagedomain.ControlCoverageReport{
		ReportType: "control_coverage", TemplateVersion: packagedomain.ControlCoverageTemplateVersion,
		FrameworkID: snapshot.FrameworkID, ProductID: filter.ProductID, ReleaseID: filter.ReleaseID,
		Result: result, Controls: items, MissingEvidence: missing, AcceptedExceptions: exceptions,
		Assumptions: []string{"Control coverage organizes technical evidence and is not a legal compliance conclusion."},
		Limitations: []string{"Coverage is based only on evidence links, exceptions, and controls recorded in this Evydence instance."},
		GeneratedAt: now,
	}, nil
}

func (s *ControlCoverageReport) CRAReadiness(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.CRAReadinessReport, error) {
	if strings.TrimSpace(productID) == "" {
		return packagedomain.CRAReadinessReport{}, ErrControlCoverageValidation
	}
	coverage, err := s.Coverage(ctx, actor, ControlCoverageFilter{ProductID: productID, ReleaseID: releaseID})
	if err != nil {
		return packagedomain.CRAReadinessReport{}, err
	}
	return packagedomain.CRAReadinessReport{
		ReportType: "cra_readiness", TemplateVersion: packagedomain.CRAReadinessTemplateVersion,
		ProductID: coverage.ProductID, ReleaseID: coverage.ReleaseID, Result: coverage.Result,
		Controls: coverage.Controls, MissingEvidence: coverage.MissingEvidence,
		AcceptedExceptions: coverage.AcceptedExceptions,
		Assumptions:        []string{"This report organizes technical evidence for CRA readiness review and is not a legal compliance conclusion."},
		Limitations: []string{
			"Readiness is based only on evidence, mappings, exceptions, and release records in this Evydence instance.",
			"Evidence presence does not prove SBOM completeness, scanner authority, secure release status, or legal sufficiency.",
		},
		GeneratedAt: coverage.GeneratedAt,
	}, nil
}

func assembleControlCoverage(snapshot ControlCoverageSnapshot, releaseID string, now time.Time) ([]packagedomain.ControlCoverageItem, []string, []packagedomain.AcceptedExceptionSnapshot, string, error) {
	controls := append([]riskdomain.SecurityControl(nil), snapshot.Controls...)
	sort.Slice(controls, func(i, j int) bool {
		if controls[i].Code == controls[j].Code {
			return controls[i].ID < controls[j].ID
		}
		return controls[i].Code < controls[j].Code
	})
	controlIDs := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		if control.ID == "" || control.TenantID != snapshot.TenantID || control.FrameworkID != snapshot.FrameworkID || control.Code == "" || control.Title == "" {
			return nil, nil, nil, "", ErrControlCoverageProjection
		}
		controlIDs[control.ID] = struct{}{}
	}
	linksByControl := make(map[string][]ControlCoverageLink, len(controls))
	for _, point := range snapshot.Links {
		link := point.Link
		if _, ok := controlIDs[link.ControlID]; !ok || link.ID == "" ||
			link.TenantID != snapshot.TenantID || link.EvidenceType == "" ||
			link.SubjectType == "" || link.SubjectID == "" ||
			point.SubjectObservedAt.IsZero() ||
			link.ProductID != "" && snapshot.ScopeProductID != "" && link.ProductID != snapshot.ScopeProductID ||
			link.ReleaseID != "" && releaseID != "" && link.ReleaseID != releaseID ||
			!validControlReportConfidence(link.Confidence) {
			return nil, nil, nil, "", ErrControlCoverageProjection
		}
		linksByControl[link.ControlID] = append(linksByControl[link.ControlID], point)
	}
	exceptions := make([]packagedomain.AcceptedExceptionSnapshot, 0, len(snapshot.Exceptions))
	waived := make(map[string]riskdomain.Exception)
	for _, exception := range snapshot.Exceptions {
		if exception.ID == "" || exception.TenantID != snapshot.TenantID ||
			exception.ControlID == "" || exception.ReleaseID == "" ||
			!exception.Approved || !exception.ExpiresAt.After(now) ||
			releaseID != "" && exception.ReleaseID != releaseID {
			return nil, nil, nil, "", ErrControlCoverageProjection
		}
		exceptions = append(exceptions, reportExceptionSnapshot(exception))
		if releaseID != "" && exception.ReleaseID == releaseID {
			current, exists := waived[exception.ControlID]
			if !exists || exception.ID < current.ID {
				waived[exception.ControlID] = exception
			}
		}
	}
	sort.Slice(exceptions, func(i, j int) bool { return exceptions[i].ID < exceptions[j].ID })
	items := make([]packagedomain.ControlCoverageItem, 0, len(controls))
	missing := []string{}
	result := "passed"
	if len(controls) == 0 {
		result = "unknown"
	}
	for _, control := range controls {
		item, err := evaluateControlCoverage(control, linksByControl[control.ID], waived[control.ID], now)
		if err != nil {
			return nil, nil, nil, "", err
		}
		items = append(items, item)
		missing = append(missing, item.Missing...)
		if item.Status == "missing" || item.Status == "partial" || item.Status == "unknown" {
			result = "failed"
		}
	}
	sort.Strings(missing)
	return items, missing, exceptions, result, nil
}

func evaluateControlCoverage(control riskdomain.SecurityControl, points []ControlCoverageLink, waiver riskdomain.Exception, now time.Time) (packagedomain.ControlCoverageItem, error) {
	item := packagedomain.ControlCoverageItem{ControlID: control.ID, Code: control.Code, Title: control.Title}
	if waiver.ID != "" {
		item.Status, item.Confidence = "waived", "medium"
		item.Explanation = "approved unexpired exception waives this control for the selected scope"
		item.Limitations = []string{waiver.Reason}
		return item, nil
	}
	if len(control.EvidenceRequirements) == 0 {
		item.Status, item.Confidence = "unknown", "unsupported"
		item.Missing = []string{"evidence_requirement"}
		item.Explanation = "control has no evidence requirements"
		item.Limitations = append([]string(nil), control.Limitations...)
		return item, nil
	}
	linked := make([]packagedomain.ControlEvidenceSnapshot, 0, len(points))
	missing := []string{}
	bestConfidence := "unsupported"
	seenRequirements := make(map[string]struct{}, len(control.EvidenceRequirements))
	for _, requirement := range control.EvidenceRequirements {
		if !supportedControlReportEvidenceType(requirement.Type) || requirement.FreshnessDays < 0 || requirement.FreshnessDays > 3650 {
			return packagedomain.ControlCoverageItem{}, ErrControlCoverageProjection
		}
		if _, duplicate := seenRequirements[requirement.Type]; duplicate {
			return packagedomain.ControlCoverageItem{}, ErrControlCoverageProjection
		}
		seenRequirements[requirement.Type] = struct{}{}
		if !requirement.Required {
			continue
		}
		matches := 0
		for _, point := range points {
			if point.Link.EvidenceType != requirement.Type {
				continue
			}
			matches++
			linked = append(linked, reportControlEvidenceSnapshot(point.Link))
			if controlReportConfidenceRank(point.Link.Confidence) > controlReportConfidenceRank(bestConfidence) {
				bestConfidence = point.Link.Confidence
			}
			if requirement.FreshnessDays > 0 && point.SubjectObservedAt.Before(now.Add(-time.Duration(requirement.FreshnessDays)*24*time.Hour)) {
				missing = append(missing, "fresh_"+requirement.Type)
			}
		}
		if matches == 0 {
			missing = append(missing, requirement.Type)
		}
	}
	sort.Slice(linked, func(i, j int) bool { return linked[i].ID < linked[j].ID })
	sort.Strings(missing)
	item.LinkedEvidence, item.Missing = linked, missing
	item.Confidence = bestConfidence
	item.Limitations = append([]string(nil), control.Limitations...)
	item.Status, item.Explanation = "satisfied", "required control evidence is present"
	if len(linked) == 0 {
		item.Status, item.Explanation = "missing", "required control evidence is missing"
	} else if len(missing) > 0 {
		item.Status, item.Explanation = "partial", "some required control evidence is missing or stale"
	}
	return item, nil
}

func validControlReportConfidence(value string) bool {
	switch value {
	case "high", "medium", "low", "unsupported":
		return true
	default:
		return false
	}
}

func supportedControlReportEvidenceType(value string) bool {
	switch value {
	case "sbom", "vulnerability_scan", "vex", "vulnerability_decision",
		"artifact", "build", "build_attestation", "openapi_contract",
		"release_bundle", "exception":
		return true
	default:
		return false
	}
}

func controlReportConfidenceRank(value string) int {
	switch value {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func reportControlEvidenceSnapshot(link riskdomain.ControlEvidence) packagedomain.ControlEvidenceSnapshot {
	return packagedomain.ControlEvidenceSnapshot{
		ID: link.ID, TenantID: link.TenantID, ControlID: link.ControlID,
		EvidenceType: link.EvidenceType, SubjectType: link.SubjectType, SubjectID: link.SubjectID,
		ProductID: link.ProductID, ReleaseID: link.ReleaseID, Confidence: link.Confidence,
		Notes: link.Notes, SchemaVersion: link.SchemaVersion, CreatedAt: link.CreatedAt,
	}
}

func reportExceptionSnapshot(exception riskdomain.Exception) packagedomain.AcceptedExceptionSnapshot {
	return packagedomain.AcceptedExceptionSnapshot{
		ID: exception.ID, TenantID: exception.TenantID, ReleaseID: exception.ReleaseID,
		FindingID: exception.FindingID, ControlID: exception.ControlID, Reason: exception.Reason,
		Owner: exception.Owner, ExpiresAt: exception.ExpiresAt, Approved: exception.Approved,
		ApprovedBy: exception.ApprovedBy, ApprovedAt: exception.ApprovedAt, CreatedAt: exception.CreatedAt,
	}
}
