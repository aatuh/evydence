package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func testContract() metricContract {
	return metricContract{Schema: contractSchema, Metrics: map[string]metricSeries{
		"evydence_operations_total":   {Type: "counter", Labels: []string{"service", "operation", "outcome"}, Values: map[string][]string{"service": {"api", "worker"}, "operation": {"worker_process", "provider_sign"}, "outcome": {"succeeded", "failed"}}},
		"evydence_queue_jobs":         {Type: "gauge", Labels: []string{"service", "state"}, Values: map[string][]string{"service": {"api", "worker"}, "state": {"queued", "dead_letter"}}},
		"evydence_migration_versions": {Type: "gauge", Labels: []string{"service", "state"}, Values: map[string][]string{"service": {"api", "worker"}, "state": {"applied", "pending", "unexpected"}}},
	}}
}

func TestQueryContract(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		valid       bool
	}{
		{"process rates", `sum by (deployment) (rate(evydence_operations_total{service="worker",operation="worker_process",outcome="failed"}[5m]))`, true},
		{"shared queue maximum", `max by (deployment) (evydence_queue_jobs{state="queued"})`, true},
		{"migration state maximum", `max by (deployment, state) (evydence_migration_versions{state=~"pending|unexpected"})`, true},
		{"duplicate migration sum", `sum by (deployment) (evydence_migration_versions{state="pending"})`, false},
		{"scrape availability", `up{job=~"evydence-api|evydence-worker"} == 0`, true},
		{"placeholder metric", `absent(evydence_worker_last_success_timestamp_seconds)`, false},
		{"invalid syntax", `sum(rate(evydence_operations_total[5m])`, false},
		{"unknown label", `evydence_operations_total{tenant="synthetic"}`, false},
		{"unknown finite value", `evydence_operations_total{operation="worker_success"}`, false},
		{"impossible regex", `evydence_operations_total{operation=~"missing_.*"}`, false},
		{"dynamic metric selection", `{__name__=~"evydence_.*"}`, false},
		{"unknown aggregation label", `sum by (tenant) (rate(evydence_operations_total[5m]))`, false},
		{"gauge increase", `increase(evydence_queue_jobs[5m])`, false},
		{"duplicate queue sum", `sum by (deployment) (evydence_queue_jobs{state="queued"})`, false},
		{"uppercase queue sum", `SUM by (deployment) (evydence_queue_jobs{state="queued"})`, false},
		{"uppercase process sum", `SUM by (deployment) (rate(evydence_operations_total[5m]))`, true},
		{"uppercase experimental aggregation", `LIMITK(1, evydence_operations_total)`, false},
		{"aggregate before reset handling", `rate((sum by (deployment) (evydence_operations_total))[5m:])`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkQuery(repositoryRoot(t), tc.query, testContract())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestRunbookReferencesStayInsideRepository(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs", "runbooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docs", "runbooks", "observability.md")
	if err := os.WriteFile(path, []byte("# Monitor\n\n## Worker backlog\n\nInspect safe queue counts.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reference string
		valid     bool
	}{
		{"docs/runbooks/observability.md#worker-backlog", true},
		{"docs/runbooks/observability.md#missing", false},
		{"docs/runbooks/observability.md", false},
		{"../outside.md#worker-backlog", false},
		{"docs/../GOAL.txt#worker-backlog", false},
		{"https://example.invalid/runbook", false},
	} {
		if err := checkRunbook(root, tc.reference); (err == nil) != tc.valid {
			t.Errorf("%s valid=%v: %v", tc.reference, tc.valid, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "private.md")
	if err := os.WriteFile(outside, []byte("## Worker backlog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "docs", "runbooks", "linked.md")); err != nil {
		t.Fatal(err)
	}
	if err := checkRunbook(root, "docs/runbooks/linked.md#worker-backlog"); err == nil {
		t.Fatal("followed a runbook symlink")
	}
}

func TestScrapeProfileRejectsCredentialAndAuthorityMistakes(t *testing.T) {
	valid := `global:
  scrape_interval: 30s
  evaluation_interval: 30s
rule_files: [prometheus-rules.yaml]
scrape_configs:
  - job_name: evydence-api
    metrics_path: /v1/metrics
    scheme: http
    scrape_protocols: [PrometheusText0.0.4]
    authorization:
      type: Bearer
      credentials_file: /run/secrets/evydence_api_metrics_token
    static_configs:
      - targets: [127.0.0.1:8080]
        labels: {deployment: evydence-example}
  - job_name: evydence-worker
    metrics_path: /metrics
    scheme: http
    scrape_protocols: [PrometheusText0.0.4]
    authorization:
      type: Bearer
      credentials_file: /run/secrets/evydence_worker_metrics_token
    static_configs:
      - targets: [127.0.0.1:9091]
        labels: {deployment: evydence-example}
`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"separate credentials", valid, true},
		{"inline credential", strings.ReplaceAll(valid, "credentials_file: /run/secrets/evydence_api_metrics_token", "credentials: SYNTHETIC_SECRET"), false},
		{"shared credential", strings.ReplaceAll(valid, "evydence_worker_metrics_token", "evydence_api_metrics_token"), false},
		{"wrong API path", strings.ReplaceAll(valid, "/v1/metrics", "/metrics"), false},
		{"service override", strings.ReplaceAll(valid, "deployment: evydence-example", "deployment: evydence-example, service: api"), false},
		{"unknown YAML", strings.ReplaceAll(valid, "scrape_interval:", "scrape_intervall:"), false},
		{"multiple documents", valid + "---\n{}\n", false},
		{"remote plaintext target", strings.ReplaceAll(valid, "127.0.0.1:8080", "192.0.2.1:8080"), false},
		{"invalid target port", strings.ReplaceAll(valid, "127.0.0.1:8080", "127.0.0.1:not-a-port"), false},
		{"credential traversal", strings.ReplaceAll(valid, "/run/secrets/evydence_api_metrics_token", "/run/secrets/../private"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkScrape([]byte(tc.body))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
				t.Fatal("credential value reached diagnostic output")
			}
		})
	}
}

func TestRuleDiagnosticsAndDashboardRegressions(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contractData, err := readRepositoryFile(root, "deploy/observability/metrics-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract metricContract
	if err := json.Unmarshal(contractData, &contract); err != nil {
		t.Fatal(err)
	}
	rules, err := readRepositoryFile(root, "deploy/observability/prometheus-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"missing action", "          action:", "          ignored_action:"},
		{"missing runbook", "#exporter", "#does-not-exist"},
		{"unknown rule field", "        for:", "        unknown_hold:"},
		{"placeholder metric", "evydence_queue_overdue_jobs", "evydence_worker_last_success_timestamp_seconds"},
		{"template syntax", "summary: Evydence operational scrape is unavailable", "summary: '{{ if $value }}'"},
		{"unknown template function", "summary: Evydence operational scrape is unavailable", "summary: '{{ unknownFunction $value }}'"},
		{"negative hold", "for: 2m", "for: -2m"},
		{"duplicate group", "  - name: evydence-runtime", "  - name: evydence-runtime\n    rules: []\n  - name: evydence-runtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.ReplaceAll(string(rules), tc.from, tc.to)
			if changed == string(rules) || checkRules(root, []byte(changed), contract) == nil {
				t.Fatal("invalid rule accepted or mutation did not apply")
			}
		})
	}
	dashboard, err := readRepositoryFile(root, "deploy/observability/grafana-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"unknown panel metric", "evydence_http_outcomes_total", "evydence_worker_last_success_timestamp_seconds"},
		{"missing datasource binding", "DS_PROMETHEUS", "UNBOUND_PROMETHEUS"},
		{"queue duplication", "max by (deployment, state) (evydence_queue_jobs)", "sum by (deployment, state) (evydence_queue_jobs)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.ReplaceAll(string(dashboard), tc.from, tc.to)
			if changed == string(dashboard) || checkDashboard(root, []byte(changed), contract) == nil {
				t.Fatal("invalid dashboard accepted or mutation did not apply")
			}
		})
	}
}

func TestRepositoryExamples(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRepository(root); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPFailureAlertKeepsSignalAfterDetailedSeriesOverflow(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := readRepositoryFile(root, "deploy/observability/prometheus-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rules struct {
		Groups []struct {
			Rules []struct{ Alert, Expr string }
		}
	}
	if err := yaml.Unmarshal(data, &rules); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != "EvydenceHTTPServerFailures" {
				continue
			}
			facts, err := parseQueryFacts(t.Context(), root, rule.Expr)
			if err != nil {
				t.Fatal(err)
			}
			for _, selector := range facts.Selectors {
				if selector.Name != "evydence_http_outcomes_total" {
					continue
				}
				for _, fact := range selector.Matchers {
					matcher, err := makeLabelMatcher(fact)
					if err != nil {
						t.Fatal(err)
					}
					if matcher.name == "outcome" && matcher.op == "=" && matcher.value == "failed" {
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("server-failure alert loses its signal when detailed HTTP series overflow; use the independent failed-outcome counter")
	}
}
