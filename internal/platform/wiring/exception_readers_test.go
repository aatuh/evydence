package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresExceptionReadersBoundRecordsAndResolveCurrentParents(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-TEST"}]';UPDATE exceptions SET finding_id='finding',control_id='control',reason=repeat('x',9000000) WHERE id='exception'`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Decisions.(riskapp.ExceptionCommandReader)
		if !ok {
			t.Fatal("bounded exception reader missing")
		}
		for _, kind := range []string{"release", "finding", "control"} {
			v, err := r.ReadExceptionSubject(ctx, "tenant", kind, kind)
			if err != nil || v.ID != kind || v.Type != kind || v.TenantID != "tenant" {
				t.Fatal("current parent resolution failed", kind, v, err)
			}
			if kind != "control" && (v.ProductID != "product" || v.ReleaseID != "release") {
				t.Fatal("parent ownership lost", v)
			}
			if _, err := r.ReadExceptionSubject(ctx, "other", kind, kind); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("foreign parent exposed", kind, err)
			}
		}
		v, err := r.ReadExceptionTransitionState(ctx, "tenant", "exception")
		if err != nil || v.ID != "exception" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.FindingID != "finding" || v.ControlID != "control" || v.Approved || v.ExpiresAt.IsZero() {
			t.Fatal("metadata read depends on historical reason", v, err)
		}
		if _, err := r.ReadExceptionForApproval(ctx, "tenant", "exception"); !errors.Is(err, app.ErrValidation) {
			t.Fatal("unbounded historical reason transferred", err)
		}
		if _, err := r.ReadExceptionTransitionState(ctx, "other", "exception"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign exception state exposed", err)
		}
		if _, err := r.ReadExceptionForApproval(ctx, "other", "exception"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign exception payload exposed", err)
		}
		if _, err := r.ReadExceptionSubject(ctx, "tenant", "policy", "policy"); !errors.Is(err, app.ErrValidation) {
			t.Fatal("unsupported parent accepted", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE exceptions SET reason='Reviewed' WHERE id='exception'`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		v, err := repos.Decisions.(riskapp.ExceptionCommandReader).ReadExceptionForApproval(ctx, "tenant", "exception")
		if err != nil || v.Reason != "Reviewed" || v.Owner != "owner" || v.ReleaseID != "release" || v.FindingID != "finding" || v.ControlID != "control" || v.Approved || v.ApprovedAt != nil || v.CreatedAt.IsZero() {
			t.Fatal("bounded approval DTO changed", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
