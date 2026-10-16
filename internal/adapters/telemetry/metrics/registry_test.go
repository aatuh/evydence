package metrics

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestRegistryRecordsHTTPAndOperationalHistograms(t *testing.T) {
	routes := []string{"/v1/products/{id}"}
	r, err := New(Config{Service: "api", Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	routes[0] = "/PRIVATE_MUTATED_ROUTE"
	r.ObserveHTTP("post", "POST /v1/products/{id}", 201, 250*time.Millisecond)
	r.Observe(t.Context(), telemetry.Event{Operation: telemetry.OperationProviderSign, Outcome: telemetry.OutcomeFailed, Duration: 500 * time.Millisecond, Attempt: 3})
	metrics, err := r.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, family := range metrics {
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, pair := range metric.Label {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels["service"] != "api" {
				t.Fatal("process service label is missing or unbounded", labels)
			}
			switch family.GetName() {
			case "http_requests_total":
				if len(labels) != 4 || labels["method"] != "POST" || labels["route"] != "/v1/products/{id}" || labels["status"] != "201" || metric.GetCounter().GetValue() != 1 {
					t.Fatal("HTTP counter lost its canonical contract", labels, metric)
				}
			case "http_request_duration_seconds":
				if metric.GetHistogram().GetSampleCount() != 1 || metric.GetHistogram().GetSampleSum() != 0.25 {
					t.Fatal("HTTP duration was not recorded in seconds")
				}
			case "evydence_operations_total":
				if len(labels) != 3 || labels["operation"] != "provider_sign" || labels["outcome"] != "failed" || metric.GetCounter().GetValue() != 1 {
					t.Fatal("operation counter lost its bounded dimensions", labels)
				}
			case "evydence_operation_duration_seconds":
				if metric.GetHistogram().GetSampleCount() != 1 || metric.GetHistogram().GetSampleSum() != 0.5 {
					t.Fatal("operation duration changed")
				}
			case "evydence_operation_attempt_number":
				if len(labels) != 3 || metric.GetHistogram().GetSampleCount() != 1 || metric.GetHistogram().GetSampleSum() != 3 {
					t.Fatal("attempt number became a label or lost its numeric value", labels)
				}
			}
		}
		found[family.GetName()] = true
	}
	for _, name := range []string{"http_requests_total", "http_request_duration_seconds", "evydence_operations_total", "evydence_operation_duration_seconds", "evydence_operation_attempt_number"} {
		if !found[name] {
			t.Fatal("missing measured metric family", name)
		}
	}
	body, err := r.Snapshot(t.Context())
	if err != nil || !strings.Contains(body, "# TYPE http_requests_total counter") || strings.Contains(body, "PRIVATE") {
		t.Fatal("invalid or unsafe Prometheus exposition", err)
	}
}

func TestRegistryUnknownInputsCannotCreateUnboundedLabels(t *testing.T) {
	r, err := New(Config{Service: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10000 {
		value := fmt.Sprintf("PRIVATE_TENANT_CREDENTIAL_URL_%d", i)
		r.ObserveHTTP(value, value, 999, -time.Second)
		r.Observe(t.Context(), telemetry.Event{Operation: telemetry.Operation(value), Outcome: telemetry.Outcome(value), Duration: -time.Second})
	}
	families, err := r.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if len(family.Metric) != 1 {
			t.Fatal("unrecognized input expanded label cardinality", family.GetName(), len(family.Metric))
		}
		for _, metric := range family.Metric {
			for _, pair := range metric.Label {
				if strings.Contains(pair.GetValue(), "PRIVATE") {
					t.Fatal("input canary reached a metric label")
				}
			}
			if h := metric.GetHistogram(); h != nil && h.GetSampleSum() != 0 {
				t.Fatal("negative duration reached a histogram")
			}
		}
	}
	body, err := r.Snapshot(t.Context())
	if err != nil || strings.Contains(body, "PRIVATE") || strings.Contains(body, "tenant") || strings.Contains(body, "process_cpu") {
		t.Fatal("private/default process data reached exposition", err)
	}
}

func TestRegistryHTTPSeriesBudgetPreservesAllObservationTotals(t *testing.T) {
	routes := make([]string, MaxRoutes)
	for i := range routes {
		routes[i] = fmt.Sprintf("/v1/route/%d", i)
	}
	r, err := New(Config{Service: "api", Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	const extra = 128
	var joined sync.WaitGroup
	for i := range MaxHTTPSeries + extra {
		joined.Go(func() {
			r.ObserveHTTP(methods[(i/len(routes))%len(methods)], routes[i%len(routes)], 200, time.Millisecond)
		})
	}
	joined.Wait()
	families, err := r.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, family := range families {
		found[family.GetName()] = true
		switch family.GetName() {
		case "http_requests_total":
			if len(family.Metric) != MaxHTTPSeries+1 {
				t.Fatal("HTTP label budget or overflow bucket changed", len(family.Metric))
			}
			total := float64(0)
			for _, metric := range family.Metric {
				total += metric.GetCounter().GetValue()
			}
			if total != MaxHTTPSeries+extra {
				t.Fatal("series-budget overflow lost observations", total)
			}
		case "http_request_duration_seconds":
			count, sum := uint64(0), float64(0)
			for _, metric := range family.Metric {
				count += metric.GetHistogram().GetSampleCount()
				sum += metric.GetHistogram().GetSampleSum()
			}
			if count != MaxHTTPSeries+extra || math.Abs(sum-float64(count)*0.001) > 1e-9 {
				t.Fatal("overflow lost or changed measured durations", count, sum)
			}
		case "evydence_telemetry_series_overflow_total":
			if len(family.Metric) != 1 || family.Metric[0].GetCounter().GetValue() != extra {
				t.Fatal("overflow accounting does not explain collapsed observations")
			}
		case "evydence_http_outcomes_total":
			if len(family.Metric) != 1 || family.Metric[0].GetCounter().GetValue() != MaxHTTPSeries+extra {
				t.Fatal("global HTTP outcomes lost observations at the series limit")
			}
		}
	}
	for _, name := range []string{"http_requests_total", "http_request_duration_seconds", "evydence_telemetry_series_overflow_total", "evydence_http_outcomes_total"} {
		if !found[name] {
			t.Fatal("missing HTTP-budget accounting family", name)
		}
	}
}

func TestExpositionBoundAppliesToEveryWriterInterface(t *testing.T) {
	var output boundedExposition
	if n, err := output.WriteString(strings.Repeat("x", maxSnapshotBytes)); n != maxSnapshotBytes || err != nil {
		t.Fatal("bounded writer rejected the allowed prefix", n, err)
	}
	if n, err := output.WriteString("private-excess"); n != 0 || err == nil {
		t.Fatal("string-writer interface bypassed the snapshot bound", n, err)
	}
	if n, err := output.Write([]byte("private-excess")); n != 0 || err == nil {
		t.Fatal("byte-slice writer bypassed the snapshot bound", n, err)
	}
	if err := output.WriteByte('x'); err == nil {
		t.Fatal("byte-writer interface bypassed the snapshot bound")
	}
	if len(output.String()) != maxSnapshotBytes {
		t.Fatal("a rejected write extended the exposition")
	}
}

func TestRegistryInstancesArePrivateAndSnapshotsHonorCancellation(t *testing.T) {
	first, err := New(Config{Service: "api"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{Service: "api"})
	if err != nil {
		t.Fatal(err)
	}
	first.Observe(t.Context(), telemetry.Event{Operation: telemetry.OperationSigning, Outcome: telemetry.OutcomeSucceeded})
	body, err := second.Snapshot(t.Context())
	if err != nil || strings.Contains(body, "operation=\"signing\"") {
		t.Fatal("one process registry leaked into another", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if body, err := first.Snapshot(canceled); err != context.Canceled || body != "" {
		t.Fatal("canceled snapshot returned data", err)
	}
}

func TestRegistryRejectsUnsafeConfigurationWithoutEchoingValues(t *testing.T) {
	for _, cfg := range []Config{
		{Service: "PRIVATE_SERVICE_CANARY"},
		{Service: "api", Routes: []string{"/v1/items?PRIVATE_QUERY"}},
		{Service: "api", Routes: []string{"/v1/PRIVATE\nHEADER"}},
		{Service: "api", Routes: []string{"https://PRIVATE_HOST/v1"}},
		{Service: "api", Routes: []string{strings.Repeat("x", 10000)}},
		{Service: "api", Routes: make([]string, MaxRoutes+1)},
	} {
		if r, err := New(cfg); r != nil || err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe registry configuration was accepted or echoed", err)
		}
	}
}
