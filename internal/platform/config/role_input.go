package config

import (
	"errors"
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
}

func parseRoleInput(environment Environment, role Role) (parsedInput, error) {
	if role != API && role != Worker && role != Migrate && role != CLI {
		return parsedInput{}, ErrInvalidRole
	}
	definitions := Definitions()
	rawEnvironment, _ := environment.lookup("ENV")
	production := strings.EqualFold(strings.TrimSpace(rawEnvironment), "production")
	if production && hasUnknownProjectOption(environment, definitions) {
		return parsedInput{}, ErrUnknownOption
	}
	input := parsedInput{role: role, production: production, values: make(map[string]scalarValue)}
	for _, d := range definitions {
		if d.Roles&role == 0 {
			continue
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
			value, err = parseScalar(d, raw)
			if err != nil {
				return parsedInput{}, err
			}
		}
		if production && ((d.ForbiddenInProduction && value.boolean) || (len(d.ProductionAllowed) > 0 && !slices.Contains(d.ProductionAllowed, value.text))) {
			return parsedInput{}, ErrUnsafeProduction
		}
		input.values[d.Name] = value
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
