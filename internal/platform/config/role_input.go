package config

import (
	"errors"
	"maps"
	"slices"
	"strings"
)

var (
	ErrInvalidRole        = errors.New("invalid runtime configuration role")
	ErrMissingValue       = errors.New("required runtime configuration value is missing")
	ErrConflictingAliases = errors.New("conflicting runtime configuration aliases")
	ErrUnknownOption      = errors.New("unknown production configuration option")
	ErrUnsafeProduction   = errors.New("unsafe production configuration option")
)

// parsedInput is an owned, role-specific intermediate representation. It is not
// a public getenv substitute: command adoption must project typed configuration
// and finish endpoint, credential, path and cross-field validation first.
type parsedInput struct {
	role       Role
	production bool
	values     map[string]scalarValue
	native     nativeInputs
	database   databaseInput
	deferred   map[string]bool
	source     SourceIdentity
}

func parseRoleInput(environment Environment, role Role) (parsedInput, error) {
	return parseRoleInputDeferred(environment, role, nil)
}

func parseRoleInputDeferred(environment Environment, role Role, deferred map[string]bool) (parsedInput, error) {
	if !validRole(role) {
		return parsedInput{}, ErrInvalidRole
	}
	definitions := Definitions()
	rawEnvironment, _ := environment.lookup("ENV")
	production := strings.EqualFold(strings.TrimSpace(rawEnvironment), "production")
	if production && hasUnknownProjectOption(environment, definitions) {
		return parsedInput{}, ErrUnknownOption
	}
	input := parsedInput{role: role, production: production, values: make(map[string]scalarValue), deferred: maps.Clone(deferred), source: sourceIdentity(environment)}
	for _, d := range definitions {
		if d.Roles&role == 0 {
			continue
		}
		if deferred[d.Name] {
			input.values[d.Name] = scalarValue{}
			continue // Only a validated, nonconflicting file plan can defer this value.
		}
		raw, err := resolveAliases(environment, d)
		if err != nil {
			return parsedInput{}, err
		}
		if raw == "" || (!d.PreserveWhitespace && strings.TrimSpace(raw) == "") {
			raw = defaultFor(environment, d, production)
		}
		if strings.TrimSpace(raw) == "" && (d.Required&role != 0 || (production && d.ProductionRequired&role != 0)) {
			return parsedInput{}, ErrMissingValue
		}
		var value scalarValue
		if raw != "" {
			value, err = parseRoleValue(d, raw)
			if err != nil {
				return parsedInput{}, err
			}
		}
		if production && violatesProductionPolicy(d, value) {
			return parsedInput{}, ErrUnsafeProduction
		}
		input.values[d.Name] = value
	}
	native, err := parseNativeInputs(environment, role)
	if err != nil {
		return parsedInput{}, err
	}
	input.native = native
	if production {
		for _, d := range NativeDefinitions() {
			if d.Roles&role == 0 {
				continue
			}
			if value, present := native.selected(d); present && violatesProductionPolicy(d.Definition, value.scalar) {
				return parsedInput{}, ErrUnsafeProduction
			}
		}
	}
	if role&databaseRoles != 0 && !deferred["EVYDENCE_DATABASE_URL"] {
		database, err := parseDatabaseInput(input.values["EVYDENCE_DATABASE_URL"].text, native)
		if err != nil {
			return parsedInput{}, err
		}
		input.database = database
	}
	if err := validateLocalInput(input); err != nil {
		return parsedInput{}, err
	}
	if err := validateEndpointInput(input); err != nil {
		return parsedInput{}, err
	}
	if err := validateSigningInput(input); err != nil {
		return parsedInput{}, err
	}
	if err := validateStorageInput(input); err != nil {
		return parsedInput{}, err
	}
	if err := validateSigstoreInput(input); err != nil {
		return parsedInput{}, err
	}
	return input, nil
}

func violatesProductionPolicy(d Definition, value scalarValue) bool {
	return (d.ForbiddenInProduction && value.boolean) ||
		(len(d.ProductionAllowed) > 0 && !slices.Contains(d.ProductionAllowed, value.text))
}

func parseRoleValue(d Definition, raw string) (scalarValue, error) {
	if d.Kind != PostgresDSN {
		return parseScalar(d, raw)
	}
	// Preserve scalar bounds and exact raw bytes while deferring cross-source
	// relationships until the native and explicit database layers are known.
	bounds := d
	bounds.Kind = Text
	value, err := parseScalar(bounds, raw)
	if err != nil {
		return scalarValue{}, err
	}
	if _, err := parseDatabaseDSNParts(raw); err != nil {
		return scalarValue{}, err
	}
	return value, nil
}

func resolveAliases(environment Environment, d Definition) (string, error) {
	raw, _ := environment.lookup(d.Name)
	for _, alias := range d.Aliases {
		aliasValue, _ := environment.lookup(alias)
		if strings.TrimSpace(aliasValue) == "" {
			continue
		}
		if strings.TrimSpace(raw) == "" {
			raw = aliasValue
		} else if strings.TrimSpace(raw) != strings.TrimSpace(aliasValue) {
			return "", ErrConflictingAliases
		}
	}
	return raw, nil
}

func defaultFor(environment Environment, d Definition, production bool) string {
	if production && d.ProductionDefault != "" {
		return d.ProductionDefault
	}
	if !production && d.NonProductionDefault != "" {
		return d.NonProductionDefault
	}
	if d.DefaultWhenSet != "" {
		dependency, _ := environment.lookup(d.DefaultWhenSet)
		if strings.TrimSpace(dependency) != "" {
			return d.ConditionalDefault
		}
	}
	return d.Default
}

func hasUnknownProjectOption(environment Environment, definitions []Definition) bool {
	known := make(map[string]bool, len(definitions))
	for _, d := range definitions {
		known[d.Name] = true
		if d.FileOption != "" {
			known[d.FileOption] = true
		}
		for _, alias := range d.Aliases {
			known[alias] = true
		}
	}
	for _, name := range environment.names() {
		if strings.HasPrefix(name, "EVYDENCE_") && !known[name] {
			return true
		}
	}
	return false
}

func (parsedInput) String() string   { return "config.parsedInput{redacted}" }
func (parsedInput) GoString() string { return "config.parsedInput{redacted}" }
func (parsedInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}
