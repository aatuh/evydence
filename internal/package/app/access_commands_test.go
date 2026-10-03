package app

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func newAccessTestCommands(t *testing.T, state *packageTestState) *AccessCommands {
	t.Helper()
	commands, err := NewAccessCommands(AccessCommandConfig{Transactions: serviceAccessTransactions{runner: state}, Authorizer: packageTestAuthorizer{state: state}, Clock: application.ClockFunc(packageTestNow), IDs: application.IDGeneratorFunc(state.nextID)})
	if err != nil {
		t.Fatal(err)
	}
	return commands
}

func accessTestPackage() packagedomain.CustomerSecurityPackage {
	return packagedomain.CustomerSecurityPackage{ID: "csp_access", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", State: "generated", SchemaVersion: packagedomain.CustomerPackageSchemaVersion, ExpiresAt: packageTestNow().Add(time.Hour), Manifest: map[string]any{"evidence_ids": []string{"ev_2", "ev_1"}}, ManifestHash: "sha256:manifest"}
}

func TestFocusedPackageAccessAndReportCommitAuditAtomically(t *testing.T) {
	state := newPackageTestState()
	state.packages["csp_access"] = accessTestPackage()
	commands := newAccessTestCommands(t, state)
	report, err := commands.SecurityReviewPackageReport(t.Context(), packageTestActor(), "csp_access")
	if err != nil || report.PackageID != "csp_access" || len(report.EvidenceIDs) != 2 || report.EvidenceIDs[0] != "ev_2" || report.TemplateVersion != "security-review-package.v1.0.0" || !report.GeneratedAt.Equal(packageTestNow()) {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if state.packages["csp_access"].AccessCount != 1 || len(state.audit) != 1 || state.audit[0].EntryType != "customer_package.accessed" || state.audit[0].PayloadHash != "sha256:manifest" {
		t.Fatalf("count=%d audit=%#v", state.packages["csp_access"].AccessCount, state.audit)
	}
	state.auditErr = errPackageTestFailure
	if pkg, err := commands.AccessCustomerSecurityPackage(t.Context(), packageTestActor(), "csp_access"); !errors.Is(err, errPackageTestFailure) || pkg.ID != "" {
		t.Fatalf("pkg=%#v err=%v", pkg, err)
	}
	if state.packages["csp_access"].AccessCount != 1 || len(state.audit) != 1 {
		t.Fatal("audit failure published access effects")
	}
	state.auditErr = nil
	state.authorize = func(request application.AuthorizationRequest) error {
		if !request.ScopeOnly {
			return application.ErrForbidden
		}
		return nil
	}
	if _, err := commands.AccessCustomerSecurityPackage(t.Context(), packageTestActor(), "csp_access"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if state.packages["csp_access"].AccessCount != 1 || len(state.audit) != 1 {
		t.Fatal("resource denial published access effects")
	}
}

func TestFocusedPackageAccessRejectsInvalidStoredStateBeforeWrites(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*packagedomain.CustomerSecurityPackage)
		want   error
		report bool
	}{
		{"foreign tenant", func(p *packagedomain.CustomerSecurityPackage) { p.TenantID = "ten_other" }, ErrNotFound, false},
		{"expired", func(p *packagedomain.CustomerSecurityPackage) { p.ExpiresAt = packageTestNow() }, ErrConflict, false},
		{"counter overflow", func(p *packagedomain.CustomerSecurityPackage) { p.AccessCount = math.MaxInt32 }, ErrConflict, false},
		{"negative counter", func(p *packagedomain.CustomerSecurityPackage) { p.AccessCount = -1 }, ErrConflict, false},
		{"non-string evidence id", func(p *packagedomain.CustomerSecurityPackage) { p.Manifest["evidence_ids"] = []any{"ev_1", 3} }, ErrConflict, true},
		{"duplicate evidence id", func(p *packagedomain.CustomerSecurityPackage) { p.Manifest["evidence_ids"] = []string{"ev_1", "ev_1"} }, ErrConflict, true},
		{"evidence capacity", func(p *packagedomain.CustomerSecurityPackage) {
			p.Manifest["evidence_ids"] = make([]string, MaxSecurityReviewEvidenceIDs+1)
		}, ErrConflict, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newPackageTestState()
			pkg := accessTestPackage()
			tc.mutate(&pkg)
			state.packages[pkg.ID] = pkg
			commands := newAccessTestCommands(t, state)
			var err error
			if tc.report {
				_, err = commands.SecurityReviewPackageReport(t.Context(), packageTestActor(), pkg.ID)
			} else {
				_, err = commands.AccessCustomerSecurityPackage(t.Context(), packageTestActor(), pkg.ID)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v", err)
			}
			if state.packages[pkg.ID].AccessCount != pkg.AccessCount || len(state.audit) != 0 {
				t.Fatal("invalid state wrote access effects")
			}
		})
	}
	state := newPackageTestState()
	commands := newAccessTestCommands(t, state)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := commands.AccessCustomerSecurityPackage(ctx, packageTestActor(), "csp_access"); !errors.Is(err, context.Canceled) || state.executeCalls != 0 {
		t.Fatal(err)
	}
	if _, err := NewAccessCommands(AccessCommandConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}
