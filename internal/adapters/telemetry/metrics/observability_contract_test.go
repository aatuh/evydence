package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

var updateObservabilityContract = flag.Bool("update-observability-contract", false, "update the fixed observability metric contract from real exporter snapshots")

type observabilitySeries struct {
	Type   string              `json:"type"`
	Labels []string            `json:"labels"`
	Values map[string][]string `json:"values,omitempty"`
}

// This contract contains code-owned names and finite labels, never measurements,
// credentials, tenant metrics, route values, or production scrape contents.
func TestObservabilityMetricContract(t *testing.T) {
	contract := struct {
		Schema  string                         `json:"schema"`
		Metrics map[string]observabilitySeries `json:"metrics"`
	}{"evydence-observability-contract.v1", make(map[string]observabilitySeries)}
	allowed := map[string]bool{"service": true, "method": true, "route": true, "status": true, "operation": true, "outcome": true, "pool": true, "state": true, "le": true}
	finite := map[string]bool{"service": true, "operation": true, "outcome": true, "pool": true, "state": true, "le": true}
	for _, service := range []string{"api", "worker"} {
		r, err := New(Config{Service: service, Routes: []string{"/v1/products"}, ResourceReader: runtimeResourceFixture{
			read: func(context.Context) (telemetry.RuntimeResources, error) { return testRuntimeResources(), nil },
		}})
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range telemetry.Operations() {
			for _, outcome := range telemetry.Outcomes() {
				r.Observe(t.Context(), telemetry.Event{Operation: op, Outcome: outcome, Duration: time.Millisecond, Attempt: 1})
			}
			r.Begin(op)()
		}
		for _, status := range []int{0, 200, 400, 500} {
			r.ObserveHTTP("GET", "GET /v1/products", status, time.Millisecond)
		}
		body, err := r.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		parser := expfmt.NewTextParser(model.UTF8Validation)
		families, err := parser.TextToMetricFamilies(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for name, family := range families {
			for _, metric := range family.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					if !allowed[label.GetName()] {
						t.Fatalf("unexpected exporter label on %s", name)
					}
					labels[label.GetName()] = label.GetValue()
				}
				add := func(sample, kind string, sampleLabels map[string]string) {
					series := contract.Metrics[sample]
					if series.Type != "" && series.Type != kind {
						t.Fatalf("inconsistent metric type: %s", sample)
					}
					series.Type = kind
					if series.Values == nil {
						series.Values = make(map[string][]string)
					}
					for label, value := range sampleLabels {
						if !slices.Contains(series.Labels, label) {
							series.Labels = append(series.Labels, label)
						}
						if finite[label] && !slices.Contains(series.Values[label], value) {
							series.Values[label] = append(series.Values[label], value)
							slices.Sort(series.Values[label])
						}
					}
					slices.Sort(series.Labels)
					contract.Metrics[sample] = series
				}
				if histogram := metric.GetHistogram(); histogram != nil {
					add(name+"_sum", "histogram_sum", labels)
					add(name+"_count", "histogram_count", labels)
					for _, bucket := range histogram.GetBucket() {
						labels["le"] = strconv.FormatFloat(bucket.GetUpperBound(), 'g', -1, 64)
						add(name+"_bucket", "histogram_bucket", labels)
					}
					labels["le"] = "+Inf"
					add(name+"_bucket", "histogram_bucket", labels)
				} else {
					add(name, strings.ToLower(family.GetType().String()), labels)
				}
			}
		}
	}
	encoded, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("..", "..", "..", "..", "deploy", "observability", "metrics-contract.json")
	if *updateObservabilityContract {
		if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
			t.Fatal("metric contract must be a regular file")
		} else if statErr != nil && !os.IsNotExist(statErr) {
			t.Fatal(statErr)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, encoded) {
		t.Fatal("observability metric contract differs from actual exporter; review the change and regenerate with -update-observability-contract")
	}
}
