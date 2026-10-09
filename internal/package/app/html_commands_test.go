package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestHTMLReportCommandsUseNarrowPortsAndAtomicWrites(t *testing.T) {
	state := newPackageTestState()
	state.craHTMLSnapshot = CRAReadinessHTMLSnapshot{SnapshotVersion: CRAReadinessHTMLSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Result: "<script>alert('x')</script>", Limitations: []string{`<img src=x onerror="alert(1)">`}}
	local := newPackageTestService(t, state)
	commands, err := NewHTMLReportCommands(HTMLReportCommandConfig{Reader: serviceHTMLReportReader{reader: state}, Transactions: serviceHTMLReportTransactions{transactions: state}, Authorizer: local.authorizer, Hasher: packageTestCanonicalizer{}, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	report, err := commands.CRAReadinessHTMLPackage(t.Context(), packageTestActor(), " prod_1 ", "rel_1")
	if err != nil || strings.Contains(report.HTML, "<script>") || strings.Contains(report.HTML, "<img") || !strings.Contains(report.HTML, "&lt;script&gt;") || report.Hash == "" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if state.craHTMLSnapshotReads != 1 || len(state.htmlReports) != 1 || len(state.audit) != 1 || state.audit[0].PayloadHash != report.Hash {
		t.Fatal("report and matching audit were not committed together")
	}
	state.auditErr = errPackageTestFailure
	if report, err := commands.CRAReadinessHTMLPackage(t.Context(), packageTestActor(), "prod_1", "rel_1"); !errors.Is(err, errPackageTestFailure) || report.ID != "" || len(state.htmlReports) != 1 {
		t.Fatalf("rollback report=%#v err=%v", report, err)
	}
}

func TestHTMLReportCommandsRejectBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*packageTestState)
		want   error
	}{
		{"foreign tenant", func(s *packageTestState) { s.craHTMLSnapshot.TenantID = "ten_other" }, ErrNotFound},
		{"foreign product", func(s *packageTestState) { s.craHTMLSnapshot.ProductID = "prod_other" }, ErrNotFound},
		{"foreign release", func(s *packageTestState) { s.craHTMLSnapshot.ReleaseID = "rel_other" }, ErrNotFound},
		{"wrong version", func(s *packageTestState) { s.craHTMLSnapshot.SnapshotVersion = "future" }, ErrConflict},
		{"escaping expands result", func(s *packageTestState) { s.craHTMLSnapshot.Result = strings.Repeat("<", MaxGeneratedReportBytes/2) }, ErrValidation},
		{"escaping expands limitation", func(s *packageTestState) {
			s.craHTMLSnapshot.Limitations = []string{strings.Repeat("&", MaxGeneratedReportBytes/2)}
		}, ErrValidation},
		{"authorization denied", func(s *packageTestState) {
			s.authorize = func(application.AuthorizationRequest) error { return application.ErrForbidden }
		}, application.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newPackageTestState()
			state.craHTMLSnapshot = CRAReadinessHTMLSnapshot{SnapshotVersion: CRAReadinessHTMLSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Result: "unknown"}
			tc.mutate(state)
			local := newPackageTestService(t, state)
			commands, err := NewHTMLReportCommands(HTMLReportCommandConfig{Reader: serviceHTMLReportReader{reader: state}, Transactions: serviceHTMLReportTransactions{transactions: state}, Authorizer: local.authorizer, Hasher: packageTestCanonicalizer{}, Clock: local.clock, IDs: local.ids})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := commands.CRAReadinessHTMLPackage(context.Background(), packageTestActor(), "prod_1", "rel_1"); !errors.Is(err, tc.want) || result.ID != "" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if state.executeCalls != 0 || len(state.htmlReports) != 0 || len(state.audit) != 0 {
				t.Fatal("invalid input reached writes")
			}
			if errors.Is(tc.want, application.ErrForbidden) && state.craHTMLSnapshotReads != 0 {
				t.Fatal("unauthorized snapshot read")
			}
		})
	}
}

type htmlTestHasher func(context.Context, []byte) (string, error)

func (f htmlTestHasher) HashPackageBytes(ctx context.Context, body []byte) (string, error) {
	return f(ctx, body)
}

func TestHTMLReportCommandsPropagateCancellationHashAndReauthorizationFailures(t *testing.T) {
	state := newPackageTestState()
	state.craHTMLSnapshot = CRAReadinessHTMLSnapshot{SnapshotVersion: CRAReadinessHTMLSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", Result: "unknown"}
	local := newPackageTestService(t, state)
	config := HTMLReportCommandConfig{Reader: serviceHTMLReportReader{state}, Transactions: serviceHTMLReportTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Clock: local.clock, IDs: local.ids}
	commands, err := NewHTMLReportCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := commands.CRAReadinessHTMLPackage(ctx, packageTestActor(), "prod_1", ""); !errors.Is(err, context.Canceled) || state.craHTMLSnapshotReads != 0 {
		t.Fatalf("cancel err=%v", err)
	}
	for _, hashErr := range []error{nil, errPackageTestFailure} {
		config.Hasher = htmlTestHasher(func(context.Context, []byte) (string, error) { return "", hashErr })
		commands, err := NewHTMLReportCommands(config)
		if err != nil {
			t.Fatal(err)
		}
		want := hashErr
		if want == nil {
			want = ErrValidation
		}
		if _, err := commands.CRAReadinessHTMLPackage(t.Context(), packageTestActor(), "prod_1", ""); !errors.Is(err, want) || state.executeCalls != 0 {
			t.Fatalf("hash err=%v", err)
		}
	}
	config.Hasher = local.canonicalizer
	commands, err = NewHTMLReportCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	state.authorize = func(application.AuthorizationRequest) error {
		checks++
		if checks == 2 {
			return application.ErrForbidden
		}
		return nil
	}
	if result, err := commands.CRAReadinessHTMLPackage(t.Context(), packageTestActor(), "prod_1", ""); !errors.Is(err, application.ErrForbidden) || result.ID != "" || checks != 2 || len(state.htmlReports) != 0 || len(state.audit) != 0 {
		t.Fatalf("reauthorization result=%#v err=%v checks=%d", result, err, checks)
	}
	for _, mutate := range []func(*HTMLReportCommandConfig){func(c *HTMLReportCommandConfig) { c.Reader = nil }, func(c *HTMLReportCommandConfig) { c.Transactions = nil }, func(c *HTMLReportCommandConfig) { c.Authorizer = nil }, func(c *HTMLReportCommandConfig) { c.Hasher = nil }, func(c *HTMLReportCommandConfig) { c.Clock = nil }, func(c *HTMLReportCommandConfig) { c.IDs = nil }} {
		invalid := config
		mutate(&invalid)
		if _, err := NewHTMLReportCommands(invalid); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid command dependencies accepted")
		}
	}
}
