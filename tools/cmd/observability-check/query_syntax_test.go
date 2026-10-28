package main

import (
	"testing"
)

func TestPromQLQuotedStringsAndRegexes(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`"worker\x5fprocess"`, "worker_process"},
		{`'worker\x5fprocess'`, "worker_process"},
		{"`literal\\path`", `literal\path`},
		{`"a\nline"`, "a\nline"},
	} {
		value, err := unquotePromString(tc.input)
		if err != nil || value != tc.want {
			t.Fatalf("quoted-string decoding mismatch: %v", err)
		}
	}
	for _, input := range []string{`"bad\z"`, `'unterminated`, `plain`} {
		if _, err := unquotePromString(input); err == nil {
			t.Fatal("invalid quoted string accepted")
		}
	}
	for _, input := range []string{`"(?=x)"`, `"(a)\1"`} {
		if _, err := makeLabelMatcher(matcherFact{Name: "job", Value: input, Op: "=~"}); err == nil {
			t.Fatal("non-RE2 expression accepted")
		}
	}
}

func TestPromQLDurationAndDisabledFeatureChecks(t *testing.T) {
	for _, tc := range []struct {
		text     string
		positive bool
		valid    bool
	}{
		{"5m", true, true}, {"1m30s", true, true}, {"30", true, true}, {"0.5", true, true},
		{"+5m", false, true},
		{"0s", true, false}, {"0s", false, true}, {"-5m", false, true}, {"-5m", true, false},
		{"0.5m", true, false}, {"1m+1m", true, false}, {"step()", true, false}, {"1e309", false, false},
	} {
		facts := queryFacts{Durations: []durationFact{{Text: tc.text, Positive: tc.positive}}}
		if err := validateQuerySyntax(facts); (err == nil) != tc.valid {
			t.Errorf("duration %s positive=%v valid=%v: %v", tc.text, tc.positive, tc.valid, err)
		}
	}
	for _, name := range []string{"info", "sort_by_label", "step", "range"} {
		if validateQuerySyntax(queryFacts{Functions: []string{name}}) == nil {
			t.Fatal("experimental function accepted without an enabled feature")
		}
	}
}
