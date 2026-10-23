package config

import (
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// nativeValue retains exact supplied bytes alongside a parsed primitive.
// Presence belongs to the containing map, including explicit empty values.
type nativeValue struct {
	redactedValue
	raw      string
	scalar   scalarValue
	endpoint url.URL
	items    []string
	ports    []uint16
}

// nativeInputs is private intermediate state, never a public getenv adapter.
// Dedicated endpoint/list checks, effective settings and typed projections must
// finish before Configuration construction is exposed to runtime composition.
type nativeInputs struct {
	redactedValue
	values map[string]nativeValue
}

func parseNativeInputs(environment Environment, role Role) (nativeInputs, error) {
	if !validRole(role) {
		return nativeInputs{}, ErrInvalidRole
	}
	input := nativeInputs{values: make(map[string]nativeValue)}
	for _, d := range NativeDefinitions() {
		if d.Roles&role == 0 {
			continue
		}
		for _, name := range append([]string{d.Name}, d.Fallbacks...) {
			raw, exists := environment.lookup(name)
			if !exists {
				continue
			}
			value, err := parseNativeValue(d, raw)
			if err != nil {
				return nativeInputs{}, err
			}
			input.values[name] = value
		}
	}
	return input, nil
}

// selected preserves native first-nonempty precedence while values retains all
// supplied spellings. It introduces no driver defaults or external resolution.
func (input nativeInputs) selected(d NativeDefinition) (nativeValue, bool) {
	for _, name := range append([]string{d.Name}, d.Fallbacks...) {
		if value, exists := input.values[name]; exists && value.raw != "" {
			return value, true
		}
	}
	return nativeValue{}, false
}

func parseNativeScalar(d NativeDefinition, raw string) (nativeValue, error) {
	// Reuse the shared byte/UTF-8/NUL guard before native-specific grammar.
	text, err := parseScalar(Definition{Kind: Text, MaxBytes: d.MaxBytes}, raw)
	if err != nil {
		return nativeValue{}, err
	}
	if d.RejectControl && strings.ContainsFunc(raw, unicode.IsControl) {
		return nativeValue{}, ErrInvalidValue
	}
	if raw == "" {
		if d.RejectEmpty {
			return nativeValue{}, ErrInvalidValue // LookupEnv presence is significant.
		}
		return nativeValue{}, nil
	}
	value := nativeValue{raw: raw, scalar: text}
	switch d.Kind {
	case Choice:
		for _, allowed := range d.Allowed {
			exact := d.CaseSensitive || slices.Contains(d.ExactChoices, allowed)
			if raw == allowed || (!exact && strings.EqualFold(raw, allowed)) {
				value.scalar.text = allowed
				return value, nil
			}
		}
		return nativeValue{}, ErrInvalidValue
	case Boolean, Integer, Seconds, Duration:
		// Native loaders parse these without project-style whitespace trimming.
		if raw != strings.TrimSpace(raw) {
			return nativeValue{}, ErrInvalidValue
		}
		value.scalar, err = parseScalar(d.Definition, raw)
		if err != nil {
			return nativeValue{}, err
		}
	case Path:
		if strings.TrimSpace(raw) == "" {
			return nativeValue{}, ErrInvalidValue
		}
	case Text:
		// Opaque text retains exact bytes, including spaces in authorization
		// values. Header/file control restrictions come from schema policy.
	case URL:
		// Retain bounded raw input for the dedicated native endpoint policy.
	default:
		return nativeValue{}, ErrInvalidValue
	}
	return value, nil
}
