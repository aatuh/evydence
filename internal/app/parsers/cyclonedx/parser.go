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
	ParserVersion        = "cyclonedx-json.v1.1.0"
)

var ErrInvalid = errors.New("invalid CycloneDX document")

type Limits struct {
	MaxBytes        int64
	MaxDepth        int
	MaxComponents   int
	MaxDependencies int
	MaxStringBytes  int
	MaxValues       int
}

func DefaultLimits(maxBytes int64) Limits {
	return Limits{
		MaxBytes:        maxBytes,
		MaxDepth:        64,
		MaxComponents:   100_000,
		MaxDependencies: 200_000,
		MaxStringBytes:  1 << 20,
		MaxValues:       1_000_000,
	}
}

type Component struct {
	Identity string
	BOMRef   string
	Type     string
	Name     string
	Version  string
	PURL     string
}

type Dependency struct {
	Ref       string
	DependsOn []string
}

type Result struct {
	SpecVersion      string
	Components       []Component
	Dependencies     []Dependency
	Warnings         []string
	UnsupportedPaths []string
}

// ParseBounded parses an in-memory CycloneDX JSON document. Upload and worker
// paths should prefer ParseBoundedReader so file-backed payloads do not require
// an additional raw-byte copy before parsing.
func ParseBounded(raw []byte, limits Limits) (Result, error) {
	return ParseBoundedReader(bytes.NewReader(raw), limits)
}

// ParseBoundedReader parses the supported CycloneDX JSON profile without
// rejecting standard fields that Evydence does not normalize. The limited
// reader gives the parser a hard byte boundary even when the caller supplies an
// unbounded stream. Official-schema validation is layered on top of this
// bounded structural pass by the package validator.
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

func validateLimits(limits Limits) error {
	if limits.MaxBytes < 1 || limits.MaxDepth < 1 || limits.MaxComponents < 1 ||
		limits.MaxDependencies < 1 || limits.MaxStringBytes < 1 || limits.MaxValues < 1 {
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
	*count++
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
		component := Component{
			BOMRef:  strings.TrimSpace(stringValue(item["bom-ref"])),
			Type:    strings.TrimSpace(stringValue(item["type"])),
			Name:    strings.TrimSpace(stringValue(item["name"])),
			Version: strings.TrimSpace(stringValue(item["version"])),
			PURL:    strings.TrimSpace(stringValue(item["purl"])),
		}
		if component.Name == "" || component.Type == "" {
			return nil, ErrInvalid
		}
		component.Identity = componentIdentity(component)
		components = append(components, component)
	}
	return components, nil
}

func componentIdentity(component Component) string {
	if component.PURL != "" {
		return "purl:" + component.PURL
	}
	if component.BOMRef != "" {
		return "bom-ref:" + component.BOMRef
	}
	return "component:" + component.Type + ":" + component.Name + "@" + component.Version
}

func parseDependencies(value any, limits Limits) ([]Dependency, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limits.MaxDependencies {
		return nil, ErrInvalid
	}
	dependencies := make([]Dependency, 0, len(rows))
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
		sort.Strings(dependsOn)
		dependencies = append(dependencies, Dependency{Ref: ref, DependsOn: dependsOn})
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Ref < dependencies[j].Ref })
	return dependencies, nil
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

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func unsupportedPaths(root map[string]any) []string {
	var paths []string
	for _, key := range []string{
		"annotations", "compositions", "declarations", "externalReferences",
		"formulation", "services", "signature", "vulnerabilities",
	} {
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
			for _, key := range []string{"evidence", "externalReferences", "hashes", "licenses", "pedigree", "properties"} {
				if value, ok := item[key]; ok && value != nil {
					paths = append(paths, "components[]."+key)
				}
			}
		}
	}
	sort.Strings(paths)
	paths = compactStrings(paths)
	return paths
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
