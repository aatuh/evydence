// Command observability-check validates the repository's offline monitoring
// examples. It never opens credential files, contacts targets, or writes files.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/common/model"
	"go.yaml.in/yaml/v3"
)

const contractSchema = "evydence-observability-contract.v1"

type metricSeries struct {
	Type   string              `json:"type"`
	Labels []string            `json:"labels"`
	Values map[string][]string `json:"values,omitempty"`
}

type metricContract struct {
	Schema  string                  `json:"schema"`
	Metrics map[string]metricSeries `json:"metrics"`
}

func main() {
	root := flag.String("root", "..", "repository root (run from the tools module)")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "observability-check accepts only --root")
		os.Exit(2)
	}
	if err := checkRepository(*root); err != nil {
		fmt.Fprintln(os.Stderr, "observability-check:", err)
		os.Exit(1)
	}
	fmt.Println("observability examples: metric contract, PromQL, rules, scrape profile, dashboard and runbooks passed (offline)")
}

// Inputs are a small, fixed set of repository files. Reject symlinks and bound
// reads before decoding; even a bad reference cannot read an operator secret.
func readRepositoryFile(root, relative string) ([]byte, error) {
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") {
		return nil, errors.New("invalid repository-relative path")
	}
	path := filepath.Join(root, relative)
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return nil, errors.New("repository input is missing or contains a symlink")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return nil, errors.New("repository input must be a bounded regular file")
	}
	f, err := os.OpenInRoot(root, relative)
	if err != nil {
		return nil, errors.New("cannot open repository input")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("cannot read bounded repository input")
	}
	return data, nil
}

func checkRepository(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return errors.New("invalid repository root")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("repository root is missing")
	}
	read := func(name string) ([]byte, error) {
		return readRepositoryFile(root, filepath.Join("deploy", "observability", name))
	}
	data, err := read("metrics-contract.json")
	if err != nil {
		return err
	}
	var contract metricContract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&contract) != nil || contract.Schema != contractSchema || len(contract.Metrics) == 0 {
		return errors.New("invalid generated metric contract")
	}
	for _, name := range []string{"prometheus.yaml", "prometheus-rules.yaml", "grafana-dashboard.json"} {
		data, err := read(name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch name {
		case "prometheus.yaml":
			err = checkScrape(data)
		case "prometheus-rules.yaml":
			err = checkRules(root, data, contract)
		case "grafana-dashboard.json":
			err = checkDashboard(root, data, contract)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func knownLabel(name string, contract metricContract) bool {
	if slices.Contains([]string{"job", "instance", "deployment"}, name) {
		return true
	}
	for _, metric := range contract.Metrics {
		if slices.Contains(metric.Labels, name) {
			return true
		}
	}
	return false
}

func checkQuery(root, query string, contract metricContract) error {
	facts, err := parseQueryFacts(context.Background(), root, query)
	if err != nil {
		return err
	}
	for _, raw := range append(slices.Clone(facts.Grouping), facts.Matching...) {
		label, err := promToken(raw)
		if err != nil || !knownLabel(label, contract) {
			return errors.New("unknown aggregation or vector-matching label")
		}
	}
	for _, call := range facts.Calls {
		if !call.DirectMatrix {
			return errors.New("apply reset-aware functions to individual process series before aggregation")
		}
	}
	for _, selector := range facts.Selectors {
		name, err := promToken(selector.Name)
		if err != nil {
			return err
		}
		matchers := make([]labelMatcher, 0, len(selector.Matchers))
		for _, fact := range selector.Matchers {
			matcher, err := makeLabelMatcher(fact)
			if err != nil {
				return err
			}
			matchers = append(matchers, matcher)
			if name == "" && matcher.name == model.MetricNameLabel && matcher.op == "=" {
				name = matcher.value
			}
		}
		metric, ok := contract.Metrics[name]
		if name == "up" {
			metric, ok = metricSeries{Type: "gauge"}, true
		}
		if !ok {
			return errors.New("query references a metric absent from the exporter contract")
		}
		for _, matcher := range matchers {
			if matcher.name == model.MetricNameLabel {
				if matcher.op != "=" || matcher.value != name {
					return errors.New("metric selection must use one explicit emitted name")
				}
				continue
			}
			if !slices.Contains(metric.Labels, matcher.name) && !slices.Contains([]string{"job", "instance", "deployment"}, matcher.name) {
				return errors.New("query references a label absent from this metric")
			}
			if values, bounded := metric.Values[matcher.name]; bounded && !slices.ContainsFunc(values, matcher.matches) {
				return errors.New("query cannot match any code-owned value for this label")
			}
		}
		if selector.Sum && strings.HasPrefix(name, "evydence_queue_") {
			return errors.New("shared database queue gauges must not be summed across scrape targets")
		}
		if selector.Counter && metric.Type == "gauge" {
			return errors.New("reset-aware counter functions cannot interpret a retained-state gauge")
		}
	}
	return nil
}

func checkRunbook(root, reference string) error {
	parts := strings.Split(reference, "#")
	if len(parts) != 2 || parts[1] == "" || !strings.HasPrefix(parts[0], "docs/runbooks/") || !strings.HasSuffix(parts[0], ".md") {
		return errors.New("alert runbook must name a local runbook section")
	}
	data, err := readRepositoryFile(root, filepath.FromSlash(parts[0]))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "## ") {
			continue
		}
		// These owned runbooks use plain ASCII headings, without inline markup.
		anchor := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(line, "## ")), " ", "-")
		if anchor == parts[1] {
			return nil
		}
	}
	return errors.New("alert runbook section is missing")
}

func checkRules(root string, data []byte, contract metricContract) error {
	var groups ruleGroups
	if err := strictYAML(data, &groups); err != nil {
		return err
	}
	if err := groups.validate(); err != nil {
		return errors.New("invalid Prometheus rule file")
	}
	seen := make(map[string]bool)
	for _, group := range groups.Groups {
		if len(group.Rules) == 0 {
			return errors.New("empty rule group")
		}
		for _, rule := range group.Rules {
			if rule.Alert == "" || rule.Record != "" || seen[rule.Alert] || rule.For <= 0 || rule.Labels["severity"] != "ticket" {
				return errors.New("example rules require unique alerts, a hold duration and calibrated ticket severity")
			}
			seen[rule.Alert] = true
			if rule.Annotations["summary"] == "" || rule.Annotations["description"] == "" || rule.Annotations["action"] == "" {
				return errors.New("alert requires a summary, description and diagnostic action")
			}
			if err := checkRunbook(root, rule.Annotations["runbook_url"]); err != nil {
				return err
			}
			if err := checkQuery(root, rule.Expr, contract); err != nil {
				return err
			}
		}
	}
	return nil
}

func strictYAML(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if decoder.Decode(target) != nil {
		return errors.New("invalid YAML or unknown example field")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return errors.New("multiple YAML documents are not supported")
	}
	return nil
}

// A deliberately narrow profile, not a replacement for Prometheus's complete
// configuration schema. Credentials are paths only and are never opened here.
type scrapeProfile struct {
	Global struct {
		ScrapeInterval     model.Duration `yaml:"scrape_interval"`
		EvaluationInterval model.Duration `yaml:"evaluation_interval"`
		ScrapeTimeout      model.Duration `yaml:"scrape_timeout,omitempty"`
	} `yaml:"global"`
	RuleFiles []string `yaml:"rule_files"`
	Scrapes   []struct {
		Job       string   `yaml:"job_name"`
		Path      string   `yaml:"metrics_path"`
		Scheme    string   `yaml:"scheme"`
		Protocols []string `yaml:"scrape_protocols"`
		Auth      struct {
			Type string `yaml:"type"`
			File string `yaml:"credentials_file"`
		} `yaml:"authorization"`
		Static []struct {
			Targets []string          `yaml:"targets"`
			Labels  map[string]string `yaml:"labels"`
		} `yaml:"static_configs"`
	} `yaml:"scrape_configs"`
}

func checkScrape(data []byte) error {
	var profile scrapeProfile
	if err := strictYAML(data, &profile); err != nil {
		return err
	}
	if profile.Global.ScrapeInterval <= 0 || profile.Global.EvaluationInterval <= 0 || profile.Global.ScrapeTimeout < 0 || profile.Global.ScrapeTimeout > profile.Global.ScrapeInterval || !slices.Equal(profile.RuleFiles, []string{"prometheus-rules.yaml"}) || len(profile.Scrapes) != 2 {
		return errors.New("invalid example intervals, rule path or target count")
	}
	expected := map[string]string{"evydence-api": "/v1/metrics", "evydence-worker": "/metrics"}
	credentials := make(map[string]bool)
	for _, scrape := range profile.Scrapes {
		path, exists := expected[scrape.Job]
		if !exists || scrape.Path != path || scrape.Scheme != "http" || !slices.Equal(scrape.Protocols, []string{"PrometheusText0.0.4"}) || scrape.Auth.Type != "Bearer" || !strings.HasPrefix(scrape.Auth.File, "/run/secrets/") || filepath.Clean(scrape.Auth.File) != scrape.Auth.File || credentials[scrape.Auth.File] || len(scrape.Static) != 1 {
			return errors.New("example requires distinct credential files and the documented API/worker scrape authority")
		}
		delete(expected, scrape.Job)
		credentials[scrape.Auth.File] = true
		static := scrape.Static[0]
		if len(static.Targets) != 1 || len(static.Labels) != 1 || static.Labels["deployment"] != "evydence-example" {
			return errors.New("example requires one local target and the deployment grouping label only")
		}
		host, port, err := net.SplitHostPort(static.Targets[0])
		portNumber, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("HTTP example targets must use loopback; remote deployments require operator TLS configuration")
		}
	}
	return nil
}

func checkDashboard(root string, data []byte, contract metricContract) error {
	var dashboard struct {
		UID    string `json:"uid"`
		Title  string `json:"title"`
		Schema int    `json:"schemaVersion"`
		Inputs []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Plugin string `json:"pluginId"`
		} `json:"__inputs"`
		Panels []struct {
			ID          int    `json:"id"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Type        string `json:"type"`
			Datasource  struct {
				Type string `json:"type"`
				UID  string `json:"uid"`
			} `json:"datasource"`
			Targets []struct {
				Expr  string `json:"expr"`
				RefID string `json:"refId"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if json.Unmarshal(data, &dashboard) != nil || dashboard.UID != "evydence-runtime" || dashboard.Title == "" || dashboard.Schema != 39 || len(dashboard.Panels) == 0 || len(dashboard.Inputs) != 1 || dashboard.Inputs[0].Name != "DS_PROMETHEUS" || dashboard.Inputs[0].Type != "datasource" || dashboard.Inputs[0].Plugin != "prometheus" {
		return errors.New("invalid Grafana example or missing Prometheus import binding")
	}
	seen := make(map[int]bool)
	for _, panel := range dashboard.Panels {
		if panel.ID <= 0 || seen[panel.ID] || panel.Title == "" || panel.Description == "" || panel.Type != "timeseries" || panel.Datasource.Type != "prometheus" || panel.Datasource.UID != "${DS_PROMETHEUS}" || len(panel.Targets) == 0 {
			return errors.New("invalid dashboard panel structure or datasource binding")
		}
		seen[panel.ID] = true
		refs := make(map[string]bool)
		for _, target := range panel.Targets {
			if target.RefID == "" || refs[target.RefID] {
				return errors.New("dashboard target requires a unique reference")
			}
			refs[target.RefID] = true
			if err := checkQuery(root, target.Expr, contract); err != nil {
				return err
			}
		}
	}
	return nil
}
