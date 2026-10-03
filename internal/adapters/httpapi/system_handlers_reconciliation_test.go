package httpapi

import (
	"strings"
	"testing"
)

func TestPrometheusMetricsKeepsOutboxAndReconciliationMetricsCompatible(t *testing.T) {
	body := prometheusMetrics(map[string]any{
		"resource_counts":                              map[string]int{"evidence_items": 3, "releases": 2},
		"customer_portal_failed_access_count":          int64(4),
		"customer_portal_revoked_access_count":         float64(5),
		"outbox_pending_jobs":                          6,
		"outbox_running_jobs":                          int64(7),
		"outbox_terminal_jobs":                         float64(8),
		"outbox_oldest_pending_age_seconds":            9,
		"object_reconciliation_runs":                   10,
		"object_reconciliation_scanned_payloads":       int64(11),
		"object_reconciliation_missing_final_objects":  float64(12),
		"object_reconciliation_missing_staged_objects": 13,
		"object_reconciliation_digest_mismatches":      14,
		"object_reconciliation_provider_orphans":       15,
		"object_reconciliation_quarantined_payloads":   16,
		"object_reconciliation_last_run_age_seconds":   17,
	})
	for _, want := range []string{
		`evydence_resource_count{resource="evidence_items"} 3`,
		`evydence_resource_count{resource="releases"} 2`,
		"evydence_customer_portal_failed_access_count 4",
		"evydence_customer_portal_revoked_access_count 5",
		"evydence_outbox_pending_jobs 6",
		"evydence_outbox_running_jobs 7",
		"evydence_outbox_terminal_jobs 8",
		"evydence_outbox_oldest_pending_age_seconds 9",
		"evydence_object_reconciliation_runs 10",
		"evydence_object_reconciliation_scanned_payloads 11",
		"evydence_object_reconciliation_missing_final_objects 12",
		"evydence_object_reconciliation_missing_staged_objects 13",
		"evydence_object_reconciliation_digest_mismatches 14",
		"evydence_object_reconciliation_provider_orphans 15",
		"evydence_object_reconciliation_quarantined_payloads 16",
		"evydence_object_reconciliation_last_run_age_seconds 17",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("prometheus metrics missing %q:\n%s", want, body)
		}
	}
	if metricInt(struct{}{}) != 0 {
		t.Fatal("unsupported metric type did not fail closed to zero")
	}
}
