// Package vex parses the OpenVEX and CycloneDX VEX subsets Evydence
// normalizes. The original JSON remains immutable evidence; extensions and
// standard fields outside the normalized subset are intentionally retained in
// that evidence and reported as warnings rather than rejected.
package vex

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	openvex "github.com/openvex/go-vex/pkg/vex"
)

const (
	OpenVEXParserVersion   = "openvex-json.v2.0.0"
	CycloneDXParserVersion = "cyclonedx-vex-json.v2.0.0"
)

var ErrInvalid = errors.New("invalid VEX document")

type Limits struct {
	MaxBytes, MaxStringBytes           int64
	MaxDepth, MaxStatements, MaxValues int
}

func DefaultLimits(maxBytes int64) Limits {
	return Limits{MaxBytes: maxBytes, MaxStringBytes: 1 << 20, MaxDepth: 64, MaxStatements: 100000, MaxValues: 1000000}
}

type Document struct {
	Format, Author, Version string
	Statements              []Statement
	Warnings                []string
}

type Statement struct {
	Vulnerability, Status, Justification, ImpactStatement, ActionStatement string
	Products                                                               []string
}

func ParseOpenVEX(raw []byte, limits Limits) (Document, error) {
	root, err := parseRoot(raw, limits)
	if err != nil {
		return Document{}, err
	}
	// Keep parsing aligned with the maintained OpenVEX model while the bounded
	// generic pass protects against duplicate keys and resource exhaustion.
	var model openvex.VEX
	if err := json.Unmarshal(raw, &model); err != nil {
		return Document{}, ErrInvalid
	}
	if nonEmpty(root["author"]) == "" || !validTime(nonEmpty(root["timestamp"])) {
		return Document{}, ErrInvalid
	}
	rows, ok := root["statements"].([]any)
	if !ok || len(rows) == 0 || len(rows) > limits.MaxStatements {
		return Document{}, ErrInvalid
	}
	doc := Document{Format: "openvex", Author: nonEmpty(root["author"]), Version: scalar(root["version"])}
	for _, row := range rows {
		statement, err := parseOpenVEXStatement(row, limits)
		if err != nil {
			return Document{}, err
		}
		doc.Statements = append(doc.Statements, statement)
	}
	doc.Warnings = unknownWarnings(root, map[string]struct{}{"@context": {}, "@id": {}, "author": {}, "timestamp": {}, "version": {}, "statements": {}}, OpenVEXParserVersion)
	return doc, nil
}

func ParseCycloneDX(raw []byte, limits Limits) (Document, error) {
	root, err := parseRoot(raw, limits)
	if err != nil {
		return Document{}, err
	}
	// The maintained CycloneDX model guards the structural interpretation; the
	// bounded generic pass above adds duplicate-key and resource protections.
	var model cyclonedx.BOM
	if err := json.Unmarshal(raw, &model); err != nil {
		return Document{}, ErrInvalid
	}
	version := nonEmpty(root["specVersion"])
	if !strings.EqualFold(nonEmpty(root["bomFormat"]), "CycloneDX") || !supportedCycloneDXVersion(version) {
		return Document{}, ErrInvalid
	}
	rows, ok := root["vulnerabilities"].([]any)
	if !ok || len(rows) == 0 || len(rows) > limits.MaxStatements {
		return Document{}, ErrInvalid
	}
	doc := Document{Format: "cyclonedx", Author: "cyclonedx", Version: version}
	for _, row := range rows {
		statement, err := parseCycloneDXStatement(row, limits)
		if err != nil {
			return Document{}, err
		}
		doc.Statements = append(doc.Statements, statement)
	}
	doc.Warnings = unknownWarnings(root, map[string]struct{}{"$schema": {}, "bomFormat": {}, "specVersion": {}, "serialNumber": {}, "version": {}, "metadata": {}, "vulnerabilities": {}}, CycloneDXParserVersion)
	return doc, nil
}

func parseRoot(raw []byte, limits Limits) (map[string]any, error) {
	if !validLimits(limits) || int64(len(raw)) == 0 || int64(len(raw)) > limits.MaxBytes {
		return nil, ErrInvalid
	}
	if err := preflight(bytes.NewReader(raw), limits); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil || !requireEOF(dec) {
		return nil, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return root, nil
}

func parseOpenVEXStatement(value any, limits Limits) (Statement, error) {
	row, ok := value.(map[string]any)
	if !ok {
		return Statement{}, ErrInvalid
	}
	vulnerability, ok := row["vulnerability"].(map[string]any)
	if !ok {
		return Statement{}, ErrInvalid
	}
	products, err := openVEXProductIDs(row["products"], limits)
	if err != nil {
		return Statement{}, err
	}
	statement := Statement{Vulnerability: nonEmpty(vulnerability["name"]), Status: nonEmpty(row["status"]), Justification: nonEmpty(row["justification"]), ImpactStatement: nonEmpty(row["impact_statement"]), ActionStatement: nonEmpty(row["action_statement"]), Products: products}
	if statement.Vulnerability == "" || statement.Status == "" || len(statement.Products) == 0 {
		return Statement{}, ErrInvalid
	}
	if !openVEXStatus(statement.Status) {
		return Statement{}, ErrInvalid
	}
	return statement, nil
}

func parseCycloneDXStatement(value any, limits Limits) (Statement, error) {
	row, ok := value.(map[string]any)
	if !ok {
		return Statement{}, ErrInvalid
	}
	analysis, _ := row["analysis"].(map[string]any)
	status := cycloneDXStatus(nonEmpty(analysis["state"]))
	products, err := cycloneDXAffectedIDs(row["affects"], limits)
	if err != nil {
		return Statement{}, err
	}
	responses, err := stringValues(analysis["response"], limits)
	if err != nil {
		return Statement{}, err
	}
	statement := Statement{Vulnerability: nonEmpty(row["id"]), Status: status, Justification: nonEmpty(analysis["justification"]), ImpactStatement: nonEmpty(analysis["detail"]), ActionStatement: strings.Join(responses, ","), Products: products}
	return statement, nil
}

func openVEXProductIDs(value any, limits Limits) ([]string, error) {
	rows, ok := value.([]any)
	if !ok || len(rows) == 0 {
		return nil, ErrInvalid
	}
	ids := map[string]struct{}{}
	var walk func([]any) error
	walk = func(items []any) error {
		for _, item := range items {
			row, ok := item.(map[string]any)
			if !ok {
				return ErrInvalid
			}
			id := nonEmpty(row["@id"])
			if id == "" {
				return ErrInvalid
			}
			ids[id] = struct{}{}
			if children, ok := row["subcomponents"]; ok {
				nested, ok := children.([]any)
				if !ok {
					return ErrInvalid
				}
				if err := walk(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(rows); err != nil {
		return nil, err
	}
	return sortedIDs(ids, limits), nil
}

func cycloneDXAffectedIDs(value any, limits Limits) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limits.MaxStatements {
		return nil, ErrInvalid
	}
	ids := map[string]struct{}{}
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		if ref := nonEmpty(row["ref"]); ref != "" {
			ids[ref] = struct{}{}
		}
	}
	return sortedIDs(ids, limits), nil
}

func stringValues(value any, limits Limits) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limits.MaxStatements {
		return nil, ErrInvalid
	}
	out := make([]string, 0, len(rows))
	for _, item := range rows {
		text, ok := item.(string)
		if !ok || int64(len(text)) > limits.MaxStringBytes {
			return nil, ErrInvalid
		}
		out = append(out, strings.TrimSpace(text))
	}
	return out, nil
}

func preflight(reader io.Reader, limits Limits) error {
	dec := json.NewDecoder(reader)
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return ErrInvalid
	}
	count := 0
	if err := scan(dec, token, 1, limits, &count); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scan(dec *json.Decoder, token json.Token, depth int, limits Limits, count *int) error {
	*count++
	if *count > limits.MaxValues || depth > limits.MaxDepth {
		return ErrInvalid
	}
	if text, ok := token.(string); ok && int64(len(text)) > limits.MaxStringBytes {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	for dec.More() {
		if depth >= limits.MaxDepth || *count >= limits.MaxValues {
			return ErrInvalid
		}
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return ErrInvalid
			}
			text, ok := key.(string)
			if !ok || int64(len(text)) > limits.MaxStringBytes {
				return ErrInvalid
			}
			if _, duplicate := seen[text]; duplicate {
				return ErrInvalid
			}
			seen[text] = struct{}{}
		}
		value, err := dec.Token()
		if err != nil {
			return ErrInvalid
		}
		if err := scan(dec, value, depth+1, limits, count); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrInvalid
	}
	return nil
}

func validLimits(l Limits) bool {
	return l.MaxBytes > 0 && l.MaxStringBytes > 0 && l.MaxDepth > 0 && l.MaxStatements > 0 && l.MaxValues > 0
}
func requireEOF(dec *json.Decoder) bool { var extra any; return errors.Is(dec.Decode(&extra), io.EOF) }
func nonEmpty(value any) string         { text, _ := value.(string); return strings.TrimSpace(text) }
func scalar(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}
func validTime(value string) bool { _, err := time.Parse(time.RFC3339, value); return err == nil }
func openVEXStatus(status string) bool {
	switch status {
	case "affected", "not_affected", "fixed", "under_investigation":
		return true
	}
	return false
}
func cycloneDXStatus(state string) string {
	switch state {
	case "resolved", "resolved_with_pedigree":
		return "fixed"
	case "not_affected", "false_positive":
		return "not_affected"
	case "exploitable":
		return "affected"
	case "in_triage":
		return "under_investigation"
	}
	return ""
}
func supportedCycloneDXVersion(version string) bool {
	switch version {
	case "1.4", "1.5", "1.6", "1.7":
		return true
	}
	return false
}
func sortedIDs(ids map[string]struct{}, limits Limits) []string {
	if len(ids) > limits.MaxStatements {
		return nil
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
func unknownWarnings(root map[string]any, known map[string]struct{}, parserVersion string) []string {
	paths := make([]string, 0)
	for key := range root {
		if _, ok := known[key]; !ok {
			paths = append(paths, "$."+key+" is preserved in raw evidence but is not normalized by parser "+parserVersion)
		}
	}
	sort.Strings(paths)
	return paths
}
