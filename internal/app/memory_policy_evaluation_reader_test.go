package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestMemoryPolicyEvaluationReaderUsesCurrentOwnedReleaseAndReadinessFacts(t *testing.T) {
	tx, expected := memoryReadinessQueryFixture(t)
	reader := tx.Repositories().PolicyEvaluationReader
	if reader == nil {
		t.Fatal("memory repositories lack focused policy evaluation reader")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	root, err := reader.ReadPolicyEvaluationRelease(t.Context(), "tenant", "tenant-release")
	if err != nil || root != (riskapp.GovernanceSubjectReference{ID: "tenant-release", TenantID: "tenant", Type: "release", ProductID: "tenant-product", ReleaseID: "tenant-release"}) {
		t.Fatal("policy evaluation reader lost current owned coordinates", root, err)
	}
	want, err := expected.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadPolicyEvaluationSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(before, tx.state) {
		t.Fatal("policy evaluation reader did not use current read-only readiness facts", err)
	}
	// Authority-only reads must not inspect malformed private readiness data.
	scan := tx.state.VulnerabilityScans["scan"]
	scan.Findings = nil
	tx.state.VulnerabilityScans[scan.ID] = scan
	if _, err := reader.ReadPolicyEvaluationRelease(t.Context(), "tenant", "tenant-release"); err != nil {
		t.Fatal("authority-only policy reader inspected scanner projections", err)
	}
	if snapshot, err := reader.ReadPolicyEvaluationSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, riskapp.ErrValidation) || !reflect.DeepEqual(snapshot, riskapp.ReadinessSnapshot{}) {
		t.Fatal("policy snapshot accepted malformed scanner projection", err)
	}
	p := tx.state.Products["tenant-product"]
	p.TenantID = "foreign"
	tx.state.Products[p.ID] = p
	if _, err := reader.ReadPolicyEvaluationRelease(t.Context(), "tenant", "tenant-release"); !errors.Is(err, riskapp.ErrNotFound) {
		t.Fatal("policy reader retained inconsistent product ownership", err)
	}
}

func TestMemoryPolicyEvaluationReaderRejectsForeignContextsAndClosedTransactions(t *testing.T) {
	tx, _ := memoryReadinessQueryFixture(t)
	reader := tx.Repositories().PolicyEvaluationReader
	if reader == nil {
		t.Fatal("memory repositories lack focused policy evaluation reader")
	}
	for _, tenant := range []string{"foreign", "missing"} {
		if _, err := reader.ReadPolicyEvaluationRelease(t.Context(), tenant, "tenant-release"); !errors.Is(err, riskapp.ErrNotFound) {
			t.Fatal("policy reader exposed foreign release", err)
		}
	}
	var absent context.Context
	if _, err := reader.ReadPolicyEvaluationRelease(absent, "tenant", "tenant-release"); !errors.Is(err, riskapp.ErrValidation) {
		t.Fatal("policy reader accepted nil context", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := reader.ReadPolicyEvaluationRelease(ctx, "tenant", "tenant-release"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, riskapp.GovernanceSubjectReference{}) {
		t.Fatal("canceled policy authority read returned coordinates", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadPolicyEvaluationRelease(t.Context(), "tenant", "tenant-release"); !errors.Is(err, ErrConflict) {
		t.Fatal("policy reader read a closed transaction", err)
	}
}
