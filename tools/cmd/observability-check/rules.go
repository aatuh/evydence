package main

import (
	"errors"
	"text/template"
	"unicode/utf8"

	"github.com/prometheus/common/model"
)

// The owned examples support this explicit alert-rule profile, not every
// Prometheus server option. KnownFields decoding rejects unsupported fields.
type ruleGroups struct {
	Groups []struct {
		Name        string            `yaml:"name"`
		Interval    model.Duration    `yaml:"interval,omitempty"`
		QueryOffset *model.Duration   `yaml:"query_offset,omitempty"`
		Limit       int               `yaml:"limit,omitempty"`
		Labels      map[string]string `yaml:"labels,omitempty"`
		Rules       []struct {
			Alert         string            `yaml:"alert,omitempty"`
			Record        string            `yaml:"record,omitempty"`
			Expr          string            `yaml:"expr"`
			For           model.Duration    `yaml:"for,omitempty"`
			KeepFiringFor model.Duration    `yaml:"keep_firing_for,omitempty"`
			Labels        map[string]string `yaml:"labels,omitempty"`
			Annotations   map[string]string `yaml:"annotations,omitempty"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

func validRuleFields(fields map[string]string, labels bool) bool {
	for name, value := range fields {
		if name == "" || !utf8.ValidString(name) || !utf8.ValidString(value) || labels && name == model.MetricNameLabel {
			return false
		}
	}
	return true
}

func (groups ruleGroups) validate() error {
	invalid := errors.New("invalid rule structure, label, duration or template")
	if len(groups.Groups) == 0 {
		return invalid
	}
	seen := make(map[string]bool)
	for _, group := range groups.Groups {
		if group.Name == "" || seen[group.Name] || !utf8.ValidString(group.Name) || group.Interval < 0 || group.QueryOffset != nil && *group.QueryOffset < 0 || group.Limit < 0 || len(group.Rules) == 0 || !validRuleFields(group.Labels, true) {
			return invalid
		}
		seen[group.Name] = true
		for _, rule := range group.Rules {
			if rule.Alert == "" || !utf8.ValidString(rule.Alert) || rule.Record != "" || rule.Expr == "" || rule.For <= 0 || rule.KeepFiringFor < 0 || !validRuleFields(rule.Labels, true) || !validRuleFields(rule.Annotations, false) {
				return invalid
			}
			for _, fields := range []map[string]string{rule.Labels, rule.Annotations} {
				for _, text := range fields {
					if err := checkAlertTemplate(text); err != nil {
						return invalid
					}
				}
			}
		}
	}
	return nil
}

// Like Prometheus template.Expander.ParseTest, validate Go template syntax
// without executing templates or queries. This is its default v0.315.1 function
// name profile; inert bodies are never executed. Unknown functions still fail.
func checkAlertTemplate(text string) error {
	functions := make(template.FuncMap)
	for _, name := range []string{
		"query", "first", "label", "value", "strvalue", "args", "reReplaceAll", "safeHtml",
		"match", "title", "toUpper", "toLower", "graphLink", "tableLink", "sortByLabel",
		"stripPort", "stripDomain", "humanize", "humanize1024", "humanizeDuration",
		"humanizePercentage", "humanizeTimestamp", "toTime", "toDuration", "now",
		"pathPrefix", "externalURL", "parseDuration", "urlQueryEscape",
	} {
		functions[name] = func(...any) any { return nil }
	}
	const variables = "{{$labels := .Labels}}{{$externalLabels := .ExternalLabels}}{{$externalURL := .ExternalURL}}{{$value := .Value}}"
	_, err := template.New("alert").Funcs(functions).Option("missingkey=zero").Parse(variables + text)
	if err != nil {
		return errors.New("invalid alert template syntax or function")
	}
	return nil
}
