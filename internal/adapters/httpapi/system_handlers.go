package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	status, err := s.ledger.ReadinessStatus(r.Context())
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	code := http.StatusOK
	if status["status"] != "ok" {
		code = http.StatusServiceUnavailable
	}
	writeData(w, code, status)
}

func (s *Server) readinessDiagnostics(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	diagnostics, err := s.ledger.ReadinessDiagnostics(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, diagnostics)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	metrics, err := s.ledger.Metrics(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		body := prometheusMetrics(metrics)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
		return
	}
	writeData(w, http.StatusOK, metrics)
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, s.identity)
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.OpenAPI()
	if err != nil {
		writeProblem(w, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

func prometheusMetrics(metrics map[string]any) string {
	var b strings.Builder
	b.WriteString("# HELP evydence_resource_count Tenant-scoped Evydence resource count.\n")
	b.WriteString("# TYPE evydence_resource_count gauge\n")
	if counts, ok := metrics["resource_counts"].(map[string]int); ok {
		keys := make([]string, 0, len(counts))
		for key := range counts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&b, "evydence_resource_count{resource=%q} %d\n", key, counts[key])
		}
	}
	b.WriteString("# HELP evydence_customer_portal_failed_access_count Tenant-scoped failed customer portal access attempts recorded against known access records.\n")
	b.WriteString("# TYPE evydence_customer_portal_failed_access_count counter\n")
	fmt.Fprintf(&b, "evydence_customer_portal_failed_access_count %d\n", metricInt(metrics["customer_portal_failed_access_count"]))
	b.WriteString("# HELP evydence_customer_portal_revoked_access_count Tenant-scoped revoked customer portal access records.\n")
	b.WriteString("# TYPE evydence_customer_portal_revoked_access_count gauge\n")
	fmt.Fprintf(&b, "evydence_customer_portal_revoked_access_count %d\n", metricInt(metrics["customer_portal_revoked_access_count"]))
	if _, ok := metrics["outbox_pending_jobs"]; ok {
		b.WriteString("# HELP evydence_outbox_pending_jobs Instance-wide queued or retrying outbox jobs.\n")
		b.WriteString("# TYPE evydence_outbox_pending_jobs gauge\n")
		fmt.Fprintf(&b, "evydence_outbox_pending_jobs %d\n", metricInt(metrics["outbox_pending_jobs"]))
		b.WriteString("# HELP evydence_outbox_running_jobs Instance-wide leased outbox jobs.\n")
		b.WriteString("# TYPE evydence_outbox_running_jobs gauge\n")
		fmt.Fprintf(&b, "evydence_outbox_running_jobs %d\n", metricInt(metrics["outbox_running_jobs"]))
		b.WriteString("# HELP evydence_outbox_terminal_jobs Instance-wide dead-letter outbox jobs.\n")
		b.WriteString("# TYPE evydence_outbox_terminal_jobs gauge\n")
		fmt.Fprintf(&b, "evydence_outbox_terminal_jobs %d\n", metricInt(metrics["outbox_terminal_jobs"]))
		b.WriteString("# HELP evydence_outbox_oldest_pending_age_seconds Age of the oldest queued or retrying outbox job.\n")
		b.WriteString("# TYPE evydence_outbox_oldest_pending_age_seconds gauge\n")
		fmt.Fprintf(&b, "evydence_outbox_oldest_pending_age_seconds %d\n", metricInt(metrics["outbox_oldest_pending_age_seconds"]))
	}
	if _, ok := metrics["object_reconciliation_runs"]; ok {
		b.WriteString("# HELP evydence_object_reconciliation_runs Tenant-scoped completed object reconciliation runs.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_runs counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_runs %d\n", metricInt(metrics["object_reconciliation_runs"]))
		b.WriteString("# HELP evydence_object_reconciliation_scanned_payloads Tenant-scoped payload metadata records scanned by reconciliation.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_scanned_payloads counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_scanned_payloads %d\n", metricInt(metrics["object_reconciliation_scanned_payloads"]))
		b.WriteString("# HELP evydence_object_reconciliation_missing_final_objects Tenant-scoped missing final-object findings.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_missing_final_objects counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_missing_final_objects %d\n", metricInt(metrics["object_reconciliation_missing_final_objects"]))
		b.WriteString("# HELP evydence_object_reconciliation_missing_staged_objects Tenant-scoped missing staging-object findings.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_missing_staged_objects counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_missing_staged_objects %d\n", metricInt(metrics["object_reconciliation_missing_staged_objects"]))
		b.WriteString("# HELP evydence_object_reconciliation_digest_mismatches Tenant-scoped object digest or metadata mismatch findings.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_digest_mismatches counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_digest_mismatches %d\n", metricInt(metrics["object_reconciliation_digest_mismatches"]))
		b.WriteString("# HELP evydence_object_reconciliation_provider_orphans Tenant-scoped provider objects without database ownership observed by advisory inventory.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_provider_orphans counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_provider_orphans %d\n", metricInt(metrics["object_reconciliation_provider_orphans"]))
		b.WriteString("# HELP evydence_object_reconciliation_quarantined_payloads Tenant-scoped lifecycle records quarantined without deleting provider objects.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_quarantined_payloads counter\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_quarantined_payloads %d\n", metricInt(metrics["object_reconciliation_quarantined_payloads"]))
		b.WriteString("# HELP evydence_object_reconciliation_last_run_age_seconds Age of the latest tenant-scoped reconciliation receipt.\n")
		b.WriteString("# TYPE evydence_object_reconciliation_last_run_age_seconds gauge\n")
		fmt.Fprintf(&b, "evydence_object_reconciliation_last_run_age_seconds %d\n", metricInt(metrics["object_reconciliation_last_run_age_seconds"]))
	}
	return b.String()
}

func metricInt(value any) int {
	switch got := value.(type) {
	case int:
		return got
	case int64:
		return int(got)
	case float64:
		return int(got)
	default:
		return 0
	}
}
