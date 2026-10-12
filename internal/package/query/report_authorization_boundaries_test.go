package query

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// The hook deterministically exercises changes between a successful scoped
// storage read and returning sensitive report contents. No sleeps or goroutines.
type reportBoundaryReader struct {
	t     *testing.T
	hook  func()
	calls int
}

func (r *reportBoundaryReader) read(ctx context.Context, tenant string) {
	r.t.Helper()
	if ctx == nil || tenant != "tenant" {
		r.t.Fatal("report read lost request context or tenant scope")
	}
	r.calls++
	if r.hook != nil {
		r.hook()
	}
}
func (r *reportBoundaryReader) ReadVulnerabilityPosture(ctx context.Context, tenant, release string) (VulnerabilityPosturePoint, error) {
	r.read(ctx, tenant)
	product := ""
	if release != "" {
		product = "product"
	}
	return VulnerabilityPosturePoint{TenantID: tenant, ProductID: product, ReleaseID: release, Summary: map[string]int{"critical": 0}}, nil
}
func (r *reportBoundaryReader) ReadControlCoverageSnapshot(ctx context.Context, tenant, framework, product, release string, _ time.Time) (ControlCoverageSnapshot, error) {
	r.read(ctx, tenant)
	return ControlCoverageSnapshot{TenantID: tenant, FrameworkID: "framework", ScopeProductID: product, ScopeReleaseID: release}, nil
}
func (r *reportBoundaryReader) ReadCRAVulnerabilitySnapshot(ctx context.Context, tenant, product, release string, _ time.Time) (CRAVulnerabilitySnapshot, error) {
	r.read(ctx, tenant)
	return CRAVulnerabilitySnapshot{TenantID: tenant, ProductID: product, ReleaseID: release}, nil
}
func (r *reportBoundaryReader) ReadReleaseReadinessReportSnapshot(ctx context.Context, tenant, release string, _ time.Time) (ReleaseReadinessReportSnapshot, error) {
	r.read(ctx, tenant)
	return ReleaseReadinessReportSnapshot{Readiness: riskdomain.ReadinessSnapshot{SnapshotVersion: riskdomain.ReadinessSnapshotVersion, TenantID: tenant, ProductID: "product", ReleaseID: release}}, nil
}
func (r *reportBoundaryReader) ReadSecurityUpdateSnapshot(ctx context.Context, tenant, product, release string) (SecurityUpdateSnapshot, error) {
	r.read(ctx, tenant)
	return SecurityUpdateSnapshot{TenantID: tenant, ProductID: product, ReleaseID: release}, nil
}
func (r *reportBoundaryReader) ReadIncidentReport(ctx context.Context, tenant, id string) (IncidentReportSnapshot, error) {
	r.read(ctx, tenant)
	status, err := operationsdomain.ParseIncidentStatus("open")
	return IncidentReportSnapshot{Incident: operationsdomain.Incident{ID: id, TenantID: tenant, ProductID: "product", ReleaseID: "release", Status: status}}, err
}

func TestPackageReportsWithholdDataAfterReadCancellationOrGrantRevocation(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
	for _, tc := range []struct {
		name string
		run  func(context.Context, identitydomain.Actor, *reportBoundaryReader) (any, error)
	}{
		{"posture", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewVulnerabilityPosture(r, now)
			if err != nil {
				return nil, err
			}
			return s.Report(ctx, a, "release")
		}},
		{"coverage", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewControlCoverageReport(r, now)
			if err != nil {
				return nil, err
			}
			return s.Coverage(ctx, a, ControlCoverageFilter{ProductID: "product", ReleaseID: "release"})
		}},
		{"cra readiness", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewControlCoverageReport(r, now)
			if err != nil {
				return nil, err
			}
			return s.CRAReadiness(ctx, a, "product", "release")
		}},
		{"cra vulnerabilities", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewCRAVulnerabilityHandling(r, now)
			if err != nil {
				return nil, err
			}
			return s.Report(ctx, a, "product", "release")
		}},
		{"release readiness", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewReleaseReadinessReport(r, now)
			if err != nil {
				return nil, err
			}
			return s.Report(ctx, a, "release")
		}},
		{"security update", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewSecurityUpdateEvidence(r, now)
			if err != nil {
				return nil, err
			}
			return s.Report(ctx, a, "product", "release")
		}},
		{"incident", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewIncidentReport(r, now)
			if err != nil {
				return nil, err
			}
			return s.Report(ctx, a, "incident")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"security:read", "report:read", "verify:read", "incident:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}}
			for _, kind := range []string{"tenant", "product", "release", "project", "customer_security_package"} {
				a := actor
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{"*"}}}
				r := &reportBoundaryReader{t: t}
				result, err := tc.run(t.Context(), a, r)
				allowed := kind == "tenant" || kind == "product" || kind == "release"
				if allowed && (err != nil || reflect.ValueOf(result).IsZero() || r.calls != 1) || !allowed && (!errors.Is(err, application.ErrForbidden) || !reflect.ValueOf(result).IsZero()) {
					t.Fatal("report changed root-grant boundary", kind, err, r.calls)
				}
			}
			reader := &reportBoundaryReader{t: t}
			if result, err := tc.run(t.Context(), actor, reader); err != nil || reflect.ValueOf(result).IsZero() || reader.calls != 1 {
				t.Fatal("authorized baseline did not produce one report", err, reader.calls)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reader.hook = cancel
			if result, err := tc.run(ctx, actor, reader); !errors.Is(err, context.Canceled) || !reflect.ValueOf(result).IsZero() || reader.calls != 2 {
				t.Error("canceled read returned report data or wrong error", err, reader.calls)
			}
			reader.hook = func() { actor.ResourceGrants[0].Scopes = nil }
			if result, err := tc.run(t.Context(), actor, reader); !errors.Is(err, application.ErrForbidden) || !reflect.ValueOf(result).IsZero() || reader.calls != 3 {
				t.Error("revoked grant returned report data or wrong error", err, reader.calls)
			}
			reader.hook = nil
			actor.UserID = ""
			if result, err := tc.run(t.Context(), actor, reader); !errors.Is(err, application.ErrUnauthorized) || !reflect.ValueOf(result).IsZero() || reader.calls != 3 {
				t.Error("missing identity reached storage or returned data", err, reader.calls)
			}
		})
	}
}

func TestTenantWidePackageReportsRecheckAuthorityAfterRead(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
	for _, tc := range []struct {
		name string
		run  func(context.Context, identitydomain.Actor, *reportBoundaryReader) (any, error)
	}{
		{"posture", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewVulnerabilityPosture(r, now)
			if err != nil {
				return nil, err
			}
			return s.Report(ctx, a, "")
		}},
		{"coverage", func(ctx context.Context, a identitydomain.Actor, r *reportBoundaryReader) (any, error) {
			s, err := NewControlCoverageReport(r, now)
			if err != nil {
				return nil, err
			}
			return s.Coverage(ctx, a, ControlCoverageFilter{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"security:read", "report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}}
			reader := &reportBoundaryReader{t: t}
			if result, err := tc.run(t.Context(), actor, reader); err != nil || reflect.ValueOf(result).IsZero() || reader.calls != 1 {
				t.Fatal("tenant-wide baseline", err, reader.calls)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reader.hook = cancel
			if result, err := tc.run(ctx, actor, reader); !errors.Is(err, context.Canceled) || !reflect.ValueOf(result).IsZero() || reader.calls != 2 {
				t.Error("canceled tenant report returned data", err, reader.calls)
			}
			reader.hook = func() { actor.ResourceGrants[0].Scopes = nil }
			if result, err := tc.run(t.Context(), actor, reader); !errors.Is(err, application.ErrForbidden) || !reflect.ValueOf(result).IsZero() || reader.calls != 3 {
				t.Error("revoked tenant report returned data", err, reader.calls)
			}
			reader.hook = nil
			for _, kind := range []string{"product", "release", "project", "customer_security_package"} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{"*"}}}
				if result, err := tc.run(t.Context(), actor, reader); !errors.Is(err, application.ErrForbidden) || !reflect.ValueOf(result).IsZero() || reader.calls != 3 {
					t.Error("scoped grant reached tenant report reader", kind, err, reader.calls)
				}
			}
		})
	}
}
