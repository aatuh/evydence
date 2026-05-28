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
	writeData(w, http.StatusOK, status)
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
	writeData(w, http.StatusOK, map[string]string{"version": "dev"})
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
