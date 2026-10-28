package main

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
)

// These feature-disabled names match the authoritative Go parser's default
// Options{} at v0.315.1. The editor grammar deliberately recognizes them too.
var disabledPromQLFunctions = []string{
	"double_exponential_smoothing", "end", "histogram_quantiles", "info", "mad_over_time",
	"max_of", "min_of", "range", "sort_by_label", "sort_by_label_desc", "start",
	"start_timestamp", "step", "ts_of_first_over_time", "ts_of_last_over_time",
	"ts_of_max_over_time", "ts_of_min_over_time",
}

// PromQL accepts Go-style double/single-quoted strings and raw backtick strings.
// Use the standard quoted-character decoder; never evaluate source as JS/code.
func unquotePromString(text string) (string, error) {
	if len(text) < 2 || text[0] != text[len(text)-1] {
		return "", errQuerySyntax
	}
	quote := text[0]
	if quote == '`' || quote == '"' {
		value, err := strconv.Unquote(text)
		if err != nil {
			return "", errQuerySyntax
		}
		return value, nil
	}
	if quote != '\'' {
		return "", errQuerySyntax
	}
	var result strings.Builder
	for body := text[1 : len(text)-1]; body != ""; {
		value, multibyte, tail, err := strconv.UnquoteChar(body, quote)
		if err != nil || len(tail) >= len(body) {
			return "", errQuerySyntax
		}
		if multibyte {
			result.WriteRune(value)
		} else {
			if value < 0 || value > 255 {
				return "", errQuerySyntax
			}
			result.WriteByte(byte(value))
		}
		body = tail
	}
	return result.String(), nil
}

func promToken(text string) (string, error) {
	if strings.HasPrefix(text, "\"") || strings.HasPrefix(text, "'") || strings.HasPrefix(text, "`") {
		return unquotePromString(text)
	}
	return text, nil
}

func promDuration(text string) (time.Duration, error) {
	sign := time.Duration(1)
	if strings.HasPrefix(text, "-") {
		sign, text = -1, text[1:]
	} else {
		text = strings.TrimPrefix(text, "+")
	}
	if value, err := strconv.ParseFloat(text, 64); err == nil {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value >= float64(math.MaxInt64)/float64(time.Second) {
			return 0, errQuerySyntax
		}
		return sign * time.Duration(value*float64(time.Second)), nil
	}
	value, err := model.ParseDuration(text)
	if err != nil {
		return 0, errQuerySyntax
	}
	return sign * time.Duration(value), nil
}

func validateQuerySyntax(facts queryFacts) error {
	if len(facts.Unsupported) != 0 {
		return errQuerySyntax
	}
	for _, function := range facts.Functions {
		if slices.Contains(disabledPromQLFunctions, function) {
			return errQuerySyntax
		}
	}
	for _, text := range facts.Strings {
		if _, err := unquotePromString(text); err != nil {
			return err
		}
	}
	for _, duration := range facts.Durations {
		value, err := promDuration(duration.Text)
		if err != nil || duration.Positive && value <= 0 {
			return errQuerySyntax
		}
	}
	for _, number := range facts.Numbers {
		if _, err := strconv.ParseFloat(number, 64); err != nil {
			if _, intErr := strconv.ParseInt(number, 0, 64); intErr != nil {
				if _, durationErr := promDuration(number); durationErr != nil {
					return errQuerySyntax
				}
			}
		}
	}
	for _, selector := range facts.Selectors {
		if len(selector.Matchers) > 128 {
			return errParserProtocol
		}
		for _, matcher := range selector.Matchers {
			if _, err := makeLabelMatcher(matcher); err != nil {
				return err
			}
		}
	}
	return nil
}

type labelMatcher struct {
	name, value, op string
	pattern         *regexp.Regexp
}

func makeLabelMatcher(fact matcherFact) (labelMatcher, error) {
	name, err := promToken(fact.Name)
	if err != nil || name == "" || !slices.Contains([]string{"=", "!=", "=~", "!~"}, fact.Op) {
		return labelMatcher{}, errQuerySyntax
	}
	value, err := unquotePromString(fact.Value)
	if err != nil {
		return labelMatcher{}, err
	}
	matcher := labelMatcher{name: name, value: value, op: fact.Op}
	if fact.Op == "=~" || fact.Op == "!~" {
		matcher.pattern, err = regexp.Compile("^(?s:" + value + ")$")
		if err != nil {
			return labelMatcher{}, errQuerySyntax
		}
	}
	return matcher, nil
}

func (m labelMatcher) matches(value string) bool {
	switch m.op {
	case "=":
		return value == m.value
	case "!=":
		return value != m.value
	case "=~":
		return m.pattern.MatchString(value)
	default:
		return !m.pattern.MatchString(value)
	}
}
