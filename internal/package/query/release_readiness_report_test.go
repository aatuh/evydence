package query

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

type readinessReportReaderFake struct {
	snapshot ReleaseReadinessReportSnapshot
	calls    int
	err      error
}

func (f *readinessReportReaderFake) ReadReleaseReadinessReportSnapshot(_ context.Context, tenantID, releaseID string, now time.Time) (ReleaseReadinessReportSnapshot, error) {
	f.calls++
	return f.snapshot, f.err
}

func TestReleaseReadinessReportUsesCanonicalPolicyAndRenderer(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reader := &readinessReportReaderFake{snapshot: ReleaseReadinessReportSnapshot{
		Readiness:           riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", HasArtifact: true, UnhandledCritical: true},
		BlockingFindings:    []packagedomain.BlockingFinding{{FindingID: "finding_1", ScanID: "scan_1", ReleaseID: "rel_1", Severity: "critical", State: "open"}},
		AcceptedExceptions:  []packagedomain.AcceptedExceptionSnapshot{{ID: "exception_1", TenantID: "ten_1", ReleaseID: "rel_1", Approved: true, ExpiresAt: now.Add(time.Hour)}},
		ActiveDecisionCount: 2,
	}}
	service, err := NewReleaseReadinessReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"verify:read"}}}}
	report, err := service.Report(t.Context(), actor, "rel_1")
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(reader.snapshot.Readiness, now)
	if err != nil {
		t.Fatal(err)
	}
	checks := make([]packagedomain.PolicyCheckSnapshot, 0, len(evaluation.Checks))
	for _, check := range evaluation.Checks {
		checks = append(checks, packagedomain.PolicyCheckSnapshot{Name: check.Name, Result: check.Result, Severity: check.Severity, Missing: check.Missing, Explanation: check.Explanation, Remediation: check.Remediation})
	}
	expected, err := packageapp.RenderReleaseReadinessReport(packageapp.ReadinessReportSnapshot{
		SnapshotVersion: packageapp.ReadinessReportSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Result: evaluation.Result, PolicySet: evaluation.PolicySet, Checks: checks,
		BlockingFindings: reader.snapshot.BlockingFindings, AcceptedExceptions: reader.snapshot.AcceptedExceptions, ActiveDecisionCount: 2,
	}, now)
	if err != nil || !reflect.DeepEqual(report, expected) || len(report.Sections) != 5 || len(report.NonClaims) == 0 {
		t.Fatalf("report=%#v expected=%#v err=%v", report, expected, err)
	}
	report.AcceptedExceptions[0].Reason = "mutated"
	report.Checks[0].Name = "mutated"
	if reader.snapshot.AcceptedExceptions[0].Reason != "" {
		t.Fatal("report aliased reader")
	}
}

func TestReleaseReadinessReportRejectsUnauthorizedAndInvalidSnapshots(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	base := ReleaseReadinessReportSnapshot{Readiness: riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1"}}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"verify:read"}}}}
	for _, tc := range []struct {
		name         string
		editActor    func(*identitydomain.Actor)
		editSnapshot func(*ReleaseReadinessReportSnapshot)
		want         error
		noRead       bool
	}{
		{"no identity", func(a *identitydomain.Actor) { a.UserID = "" }, nil, application.ErrUnauthorized, true},
		{"wrong scope", func(a *identitydomain.Actor) { a.Scopes = []string{"report:read"} }, nil, application.ErrForbidden, true},
		{"foreign grant", func(a *identitydomain.Actor) {
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_other", Scopes: []string{"verify:read"}}}
		}, nil, application.ErrForbidden, true},
		{"empty release grant", func(a *identitydomain.Actor) {
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", Scopes: []string{"verify:read"}}}
		}, nil, application.ErrForbidden, true},
		{"foreign product grant", func(a *identitydomain.Actor) {
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_other", Scopes: []string{"verify:read"}}}
		}, nil, application.ErrForbidden, false},
		{"foreign tenant", nil, func(s *ReleaseReadinessReportSnapshot) { s.Readiness.TenantID = "ten_other" }, ErrReleaseReadinessProjection, false},
		{"foreign release", nil, func(s *ReleaseReadinessReportSnapshot) { s.Readiness.ReleaseID = "rel_other" }, ErrReleaseReadinessProjection, false},
		{"negative count", nil, func(s *ReleaseReadinessReportSnapshot) { s.ActiveDecisionCount = -1 }, ErrReleaseReadinessProjection, false},
		{"foreign finding", nil, func(s *ReleaseReadinessReportSnapshot) {
			s.BlockingFindings = []packagedomain.BlockingFinding{{FindingID: "f", ScanID: "s", ReleaseID: "rel_other", Severity: "critical", State: "open"}}
		}, ErrReleaseReadinessProjection, false},
		{"expired exception", nil, func(s *ReleaseReadinessReportSnapshot) {
			s.AcceptedExceptions = []packagedomain.AcceptedExceptionSnapshot{{ID: "exc", TenantID: "ten_1", ReleaseID: "rel_1", Approved: true, ExpiresAt: now}}
		}, ErrReleaseReadinessProjection, false},
		{"capacity", nil, func(s *ReleaseReadinessReportSnapshot) {
			s.BlockingFindings = make([]packagedomain.BlockingFinding, MaxReleaseReadinessEntries+1)
		}, ErrReleaseReadinessProjection, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, snapshot := actor, base
			if tc.editActor != nil {
				tc.editActor(&a)
			}
			if tc.editSnapshot != nil {
				tc.editSnapshot(&snapshot)
			}
			reader := &readinessReportReaderFake{snapshot: snapshot}
			service, _ := NewReleaseReadinessReport(reader, func() time.Time { return now })
			if result, err := service.Report(t.Context(), a, "rel_1"); !errors.Is(err, tc.want) || result.ReportType != "" {
				t.Fatalf("report=%#v err=%v", result, err)
			}
			if tc.noRead && reader.calls != 0 {
				t.Fatal("unauthorized request reached reader")
			}
		})
	}
	reader := &readinessReportReaderFake{snapshot: base, err: errors.New("reader failed")}
	service, _ := NewReleaseReadinessReport(reader, func() time.Time { return now })
	if _, err := service.Report(t.Context(), actor, "rel_1"); !errors.Is(err, reader.err) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	before := reader.calls
	if _, err := service.Report(cancelled, actor, "rel_1"); !errors.Is(err, context.Canceled) || reader.calls != before {
		t.Fatal(err)
	}
	if _, err := NewReleaseReadinessReport(nil, time.Now); err == nil {
		t.Fatal("nil reader accepted")
	}
}
