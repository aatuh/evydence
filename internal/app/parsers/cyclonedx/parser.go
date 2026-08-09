package cyclonedx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	SupportedSpecVersion = "1.6"
	ParserVersion        = "cyclonedx-json.v1.3.2"
)

var ErrInvalid = errors.New("invalid CycloneDX document")

type Limits struct {
	MaxBytes                                                            int64
	MaxDepth, MaxComponents, MaxDependencies, MaxStringBytes, MaxValues int
}

func DefaultLimits(maxBytes int64) Limits {
	return Limits{maxBytes, 64, 100000, 200000, 1 << 20, 1000000}
}

type Component struct{ Identity, BOMRef, Type, Name, Version, PURL string }
type Dependency struct {
	Ref       string
	DependsOn []string
}
type Result struct {
	SpecVersion                string
	Components                 []Component
	Dependencies               []Dependency
	Warnings, UnsupportedPaths []string
}

func ParseBounded(raw []byte, limits Limits) (Result, error) {
	return ParseBoundedReader(bytes.NewReader(raw), limits)
}
func ParseBoundedReader(reader io.Reader, limits Limits) (Result, error) {
	if reader == nil || validateLimits(limits) != nil {
		return Result{}, ErrInvalid
	}
	limited := &io.LimitedReader{R: reader, N: limits.MaxBytes + 1}
	dec := json.NewDecoder(limited)
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return Result{}, ErrInvalid
	}
	if err := requireEOF(dec); err != nil || limited.N == 0 {
		return Result{}, ErrInvalid
	}
	count := 0
	if err := checkValueBounds(value, 1, limits, &count); err != nil {
		return Result{}, err
	}
	if err := checkComponentCount(value, limits.MaxComponents); err != nil {
		return Result{}, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Result{}, ErrInvalid
	}
	if stringValue(root["bomFormat"]) != "CycloneDX" || stringValue(root["specVersion"]) != SupportedSpecVersion {
		return Result{}, ErrInvalid
	}
	result := Result{SpecVersion: SupportedSpecVersion}
	components, err := parseComponents(root["components"], limits)
	if err != nil {
		return Result{}, err
	}
	result.Components = components
	dependencies, err := parseDependencies(root["dependencies"], limits)
	if err != nil {
		return Result{}, err
	}
	result.Dependencies = dependencies
	result.UnsupportedPaths = unsupportedPaths(root)
	for _, path := range result.UnsupportedPaths {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%s is preserved in raw evidence but is not normalized by parser %s", path, ParserVersion))
	}
	return result, nil
}
func validateLimits(l Limits) error {
	if l.MaxBytes < 1 || l.MaxDepth < 1 || l.MaxComponents < 1 || l.MaxDependencies < 1 || l.MaxStringBytes < 1 || l.MaxValues < 1 {
		return ErrInvalid
	}
	return nil
}
func requireEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
func checkValueBounds(value any, depth int, limits Limits, count *int) error {
	(*count)++
	if *count > limits.MaxValues || depth > limits.MaxDepth {
		return ErrInvalid
	}
	switch typed := value.(type) {
	case string:
		if len(typed) > limits.MaxStringBytes {
			return ErrInvalid
		}
	case []any:
		for _, item := range typed {
			if err := checkValueBounds(item, depth+1, limits, count); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range typed {
			if len(key) > limits.MaxStringBytes {
				return ErrInvalid
			}
			if err := checkValueBounds(item, depth+1, limits, count); err != nil {
				return err
			}
		}
	}
	return nil
}
func checkComponentCount(value any, limit int) error {
	count := 0
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case []any:
			for _, item := range typed {
				if err := walk(item); err != nil {
					return err
				}
			}
		case map[string]any:
			for key, item := range typed {
				switch key {
				case "components":
					rows, ok := item.([]any)
					if !ok {
						return ErrInvalid
					}
					count += len(rows)
				case "component":
					if _, ok := item.(map[string]any); !ok {
						return ErrInvalid
					}
					count++
				}
				if count > limit {
					return ErrInvalid
				}
				if err := walk(item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func parseComponents(value any, limits Limits) ([]Component, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limits.MaxComponents {
		return nil, ErrInvalid
	}
	components := make([]Component, 0, len(rows))
	for _, row := range rows {
		item, ok := row.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		c := Component{BOMRef: strings.TrimSpace(stringValue(item["bom-ref"])), Type: strings.TrimSpace(stringValue(item["type"])), Name: strings.TrimSpace(stringValue(item["name"])), Version: strings.TrimSpace(stringValue(item["version"])), PURL: strings.TrimSpace(stringValue(item["purl"]))}
		if c.Name == "" || c.Type == "" {
			return nil, ErrInvalid
		}
		c.Identity = componentIdentity(c)
		components = append(components, c)
	}
	sort.Slice(components, func(i, j int) bool {
		left, right := components[i], components[j]
		if left.Identity != right.Identity {
			return left.Identity < right.Identity
		}
		if left.BOMRef != right.BOMRef {
			return left.BOMRef < right.BOMRef
		}
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.PURL < right.PURL
	})
	return components, nil
}
func componentIdentity(c Component) string {
	if c.PURL != "" {
		return "purl:" + c.PURL
	}
	if c.BOMRef != "" {
		return "bom-ref:" + c.BOMRef
	}
	return "component:" + c.Type + ":" + c.Name + "@" + c.Version
}
func parseDependencies(value any, limits Limits) ([]Dependency, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limits.MaxDependencies {
		return nil, ErrInvalid
	}
	deps := make([]Dependency, 0, len(rows))
	edgeCount := 0
	for _, row := range rows {
		item, ok := row.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		ref := strings.TrimSpace(stringValue(item["ref"]))
		if ref == "" {
			return nil, ErrInvalid
		}
		dependsOn, err := stringArray(item["dependsOn"], limits.MaxDependencies)
		if err != nil {
			return nil, err
		}
		provides, err := stringArray(item["provides"], limits.MaxDependencies)
		if err != nil {
			return nil, err
		}
		edgeCount += len(dependsOn) + len(provides)
		if edgeCount > limits.MaxDependencies {
			return nil, ErrInvalid
		}
		sort.Strings(dependsOn)
		deps = append(deps, Dependency{ref, dependsOn})
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ref != deps[j].Ref {
			return deps[i].Ref < deps[j].Ref
		}
		return compareStringSlices(deps[i].DependsOn, deps[j].DependsOn) < 0
	})
	return deps, nil
}
func compareStringSlices(left, right []string) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for i := 0; i < limit; i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}
func stringArray(value any, limit int) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limit {
		return nil, ErrInvalid
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		value, ok := row.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, ErrInvalid
		}
		out = append(out, strings.TrimSpace(value))
	}
	return out, nil
}
func stringValue(value any) string { text, _ := value.(string); return text }
func unsupportedPaths(root map[string]any) []string {
	var paths []string
	for _, key := range []string{"$schema", "annotations", "compositions", "declarations", "definitions", "externalReferences", "formulation", "metadata", "properties", "serialNumber", "services", "signature", "version", "vulnerabilities"} {
		if value, ok := root[key]; ok && value != nil {
			paths = append(paths, key)
		}
	}
	if rows, ok := root["components"].([]any); ok {
		for _, row := range rows {
			item, ok := row.(map[string]any)
			if !ok {
				continue
			}
			for _, key := range []string{"author", "authors", "components", "copyright", "cpe", "cryptoProperties", "data", "description", "evidence", "externalReferences", "group", "hashes", "licenses", "manufacturer", "mime-type", "modelCard", "modified", "omniborId", "pedigree", "properties", "publisher", "releaseNotes", "scope", "signature", "supplier", "swhid", "swid", "tags"} {
				if value, ok := item[key]; ok && value != nil {
					paths = append(paths, "components[]."+key)
				}
			}
		}
	}
	if rows, ok := root["dependencies"].([]any); ok {
		for _, row := range rows {
			item, ok := row.(map[string]any)
			if !ok {
				continue
			}
			if value, ok := item["provides"]; ok && value != nil {
				paths = append(paths, "dependencies[].provides")
			}
		}
	}
	sort.Strings(paths)
	return compactStrings(paths)
}
func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
