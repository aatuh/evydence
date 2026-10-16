package wiring

import (
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestBuildOperationalMetricsUsesOnlyOwnedRoutesAndPrivateRegistries(t *testing.T) {
	for _, process := range []Process{API, Worker} {
		r, err := BuildOperationalMetrics(process)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range httpapi.MetricRoutes() {
			r.ObserveHTTP("GET", route, 200, time.Millisecond)
		}
		r.Observe(t.Context(), telemetry.Event{Operation: telemetry.OperationProviderSign, Outcome: telemetry.OutcomeSucceeded})
		body, err := r.Snapshot(t.Context())
		if err != nil || !strings.Contains(body, "service=\""+string(process)+"\"") || strings.Contains(body, "process_cpu") {
			t.Fatal("runtime metrics service or private registry changed", err)
		}
		if process == API && (!strings.Contains(body, "route=\"/v1/products/{id}\"") || strings.Contains(body, "route=\"unknown\"")) {
			t.Fatal("API metrics do not cover the complete owned route catalog")
		}
		if process == Worker && strings.Contains(body, "route=\"/v1/products/{id}\"") {
			t.Fatal("worker recorder accepted API route configuration")
		}
		other, err := BuildOperationalMetrics(process)
		if err != nil {
			t.Fatal(err)
		}
		body, err = other.Snapshot(t.Context())
		if err != nil || strings.Contains(body, "operation=\"provider_sign\"") {
			t.Fatal("runtime metrics registries share process observations", err)
		}
	}
	if r, err := BuildOperationalMetrics(Process("PRIVATE_PROCESS")); r != nil || err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unknown process metrics configuration was accepted or echoed", err)
	}
}
