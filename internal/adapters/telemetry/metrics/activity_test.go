package metrics

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestActivityGaugeReportsActualWorkAndResetsAfterCompletion(t *testing.T) {
	r, err := New(Config{Service: "api"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.WithObserver(t.Context(), r)
	err = telemetry.MeasureError(ctx, telemetry.OperationObjectWrite, func(callCtx context.Context) error {
		body, err := r.Snapshot(callCtx)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, `evydence_active_operations{operation="object_write",service="api"} 1`) {
			t.Fatal("active operation was not measured")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.Snapshot(t.Context())
	if err != nil || !strings.Contains(body, `evydence_active_operations{operation="object_write",service="api"} 0`) || !strings.Contains(body, `evydence_operations_total{operation="object_write",outcome="succeeded",service="api"} 1`) {
		t.Fatal("completed operation did not balance its active gauge and counter", err)
	}
}

func TestActivityNamesCannotExpandCardinalityAndReleaseIsIdempotent(t *testing.T) {
	r, err := New(Config{Service: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10000 {
		release := r.Begin(telemetry.Operation("PRIVATE_TENANT_CREDENTIAL_URL" + strconv.Itoa(i)))
		release()
		release()
	}
	families, err := r.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() == "evydence_active_operations" {
			found = true
			if len(family.Metric) != 1 || family.Metric[0].GetGauge().GetValue() != 0 {
				t.Fatal("activity gauge cardinality or release accounting changed")
			}
			for _, label := range family.Metric[0].Label {
				if strings.Contains(label.GetValue(), "PRIVATE") {
					t.Fatal("private activity label escaped")
				}
			}
		}
	}
	if !found {
		t.Fatal("active gauge missing")
	}
}
