package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var errAnomalyFixture = errors.New("anomaly transaction failure")

type anomalyFixture struct {
	scope   AnomalyScope
	facts   AnomalyReleaseFacts
	phase   string
	reads   int
	reports []experimentaldomain.AnomalyReport
	audits  []application.AuditEvent
	cancel  context.CancelFunc
}

func (f *anomalyFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "scope authorization" || !r.ScopeOnly && f.phase == "root authorization" {
		return application.ErrForbidden
	}
	return nil
}
func (f *anomalyFixture) ExecuteAnomalyReport(ctx context.Context, _ string, fn func(context.Context, AnomalyTransaction) error) error {
	r, a := len(f.reports), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errAnomalyFixture
	}
	if err != nil {
		f.reports, f.audits = f.reports[:r], f.audits[:a]
	}
	return err
}
func (f *anomalyFixture) ReadAnomalyScope(context.Context, string, string, string) (AnomalyScope, error) {
	if f.phase == "scope" {
		return AnomalyScope{}, errAnomalyFixture
	}
	return f.scope, nil
}
func (f *anomalyFixture) ReadAnomalyReleaseFacts(context.Context, string, string, time.Time) (AnomalyReleaseFacts, error) {
	f.reads++
	if f.phase == "facts" {
		return AnomalyReleaseFacts{}, errAnomalyFixture
	}
	return f.facts, nil
}
func (f *anomalyFixture) InsertAnomalyReport(_ context.Context, v experimentaldomain.AnomalyReport) error {
	if f.phase == "insert" {
		return errAnomalyFixture
	}
	f.reports = append(f.reports, v)
	return nil
}
func (f *anomalyFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errAnomalyFixture
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func anomalyCommandFixture(t *testing.T) (*AnomalyCommands, *anomalyFixture, identitydomain.Actor, AnomalyReportInput) {
	t.Helper()
	f := &anomalyFixture{scope: AnomalyScope{TenantID: "tenant", SubjectType: "release", SubjectID: "release", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}, facts: AnomalyReleaseFacts{TenantID: "tenant", ReleaseID: "release", UnhandledCritical: true}}
	n := 0
	c, err := NewAnomalyCommands(AnomalyCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 6, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}, AnomalyReportInput{SubjectType: "release", SubjectID: "release"}
}
func TestAnomalyCommandsPreserveDeterministicSignalsAndReplayGuard(t *testing.T) {
	c, f, a, in := anomalyCommandFixture(t)
	v, err := c.GenerateAnomalyReport(t.Context(), a, in)
	if err != nil || v.Result != "attention_required" || len(v.Signals) != 3 || v.Signals[0].Name != "missing_passed_build" || v.Signals[1].Name != "missing_matching_attestation" || v.Signals[2].Severity != "high" || v.CreatedAt.Nanosecond() != 123456000 || len(f.reports) != 1 || len(f.audits) != 1 || f.audits[0].EntryType != "anomaly_report.created" || f.audits[0].SubjectID != v.ID || f.audits[0].PayloadHash != "" {
		t.Fatal("anomaly contract changed", v, err)
	}
	v.Signals[0].Detail = "changed"
	v.Assumptions[0] = "changed"
	v.Limitations[0] = "changed"
	if f.reports[0].Signals[0].Detail == "changed" || f.reports[0].Assumptions[0] == "changed" || f.reports[0].Limitations[0] == "changed" {
		t.Fatal("returned anomaly record aliases storage")
	}
	if err := c.AuthorizeGenerateAnomalyReport(t.Context(), a, in); err != nil || f.reads != 1 || len(f.reports) != 1 || len(f.audits) != 1 {
		t.Fatal("replay recomputed signals", err)
	}
	f.scope.SubjectType, f.scope.SubjectID = "product", "product"
	f.scope.Resources = application.ResourceReferences{ProductID: "product"}
	in.SubjectType, in.SubjectID = "product", "product"
	clear, err := c.GenerateAnomalyReport(t.Context(), a, in)
	if err != nil || clear.Result != "clear" || len(clear.Signals) != 0 || f.reads != 1 {
		t.Fatal("non-release anomaly evaluated release facts", clear, err)
	}
	raw, err := EncodeAnomalyReport(clear)
	if err != nil || strings.Contains(string(raw), `"signals"`) || strings.Contains(string(raw), `"SubjectType"`) {
		t.Fatal("clear report JSON changed", string(raw), err)
	}
}
func TestAnomalyCommandsFailuresWithholdReportAndAudit(t *testing.T) {
	for _, phase := range []string{"scope authorization", "root authorization", "scope", "foreign scope", "facts", "foreign facts", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := anomalyCommandFixture(t)
			f.phase = phase
			want := errAnomalyFixture
			ctx := t.Context()
			switch phase {
			case "scope authorization", "root authorization":
				want = application.ErrForbidden
			case "foreign scope":
				f.scope.TenantID = "other"
				want = ErrNotFound
			case "foreign facts":
				f.facts.ReleaseID = "other"
				want = ErrNotFound
			case "cancel":
				ctx, f.cancel = context.WithCancel(ctx)
				defer f.cancel()
				want = context.Canceled
			}
			v, err := c.GenerateAnomalyReport(ctx, a, in)
			if !errors.Is(err, want) || !reflect.DeepEqual(v, experimentaldomain.AnomalyReport{}) || len(f.reports)+len(f.audits) != 0 {
				t.Fatal("failed anomaly report escaped", v, err)
			}
			if strings.Contains(phase, "authorization") || phase == "scope" || phase == "foreign scope" {
				if f.reads != 0 {
					t.Fatal("denied request read release facts")
				}
			}
		})
	}
}
func TestAnomalyNormalizationBoundsRawInput(t *testing.T) {
	for _, in := range []AnomalyReportInput{{"unknown", "id"}, {"release", ""}, {"release", strings.Repeat(" ", 1025) + "id"}, {strings.Repeat(" ", 129) + "release", "id"}, {"release", "id\x00"}, {"release", string([]byte{255})}} {
		if _, err := NormalizeAnomalyInput(in); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid anomaly input accepted", err)
		}
	}
	for _, kind := range []string{"tenant", "product", "release", "build", "evidence", "customer_package"} {
		in, err := NormalizeAnomalyInput(AnomalyReportInput{kind, " id "})
		if err != nil || in.SubjectID != "id" {
			t.Fatal("valid subject changed", in, err)
		}
	}
}
