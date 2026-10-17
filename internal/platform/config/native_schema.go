package config

import "slices"

// NativeBoundary identifies a separately owned driver/credential boundary.
// Declaring its inputs does not resolve defaults, files or provider credentials.
type NativeBoundary string

const (
	NativePostgres NativeBoundary = "postgres"
	NativeAWS      NativeBoundary = "aws"
	NativeGoogle   NativeBoundary = "google"
	NativeAzure    NativeBoundary = "azure"
	NativeHost     NativeBoundary = "host"
)

// NativeDefinition extends the shared schema metadata with the native target
// parameter and pinned source. These inputs are not aliases for project options:
// a connection string can override PG* settings using native precedence.
type NativeDefinition struct {
	Definition
	Boundary  NativeBoundary
	Parameter string
	Source    string
	// Fallbacks are lower-priority environment names. Their supplied values are
	// captured independently; they are not equality-enforcing project aliases.
	Fallbacks []string
}

var nativeInputDefinitions = slices.Concat(
	nativePostgresDefinitions(), nativeAWSDefinitions(), nativeGoogleDefinitions(),
	nativeAzureDefinitions(), nativeHostDefinitions(),
)

// NativeDefinitions returns owned, sorted native-input metadata. Like
// Definitions, it contains code-owned policy only, never operator values.
// Native parsing/resolution and command adoption remain separate steps.
func NativeDefinitions() []NativeDefinition {
	result := slices.Clone(nativeInputDefinitions)
	for i := range result {
		result[i].Allowed = slices.Clone(result[i].Allowed)
		result[i].ProductionAllowed = slices.Clone(result[i].ProductionAllowed)
		result[i].Aliases = slices.Clone(result[i].Aliases)
		result[i].Fallbacks = slices.Clone(result[i].Fallbacks)
	}
	slices.SortFunc(result, func(a, b NativeDefinition) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return result
}

func nativeEnvironmentName(name string) bool {
	for _, d := range nativeInputDefinitions {
		if d.Name == name || slices.Contains(d.Fallbacks, name) {
			return true
		}
	}
	return false
}

func nativeInput(boundary NativeBoundary, source, name, parameter string, kind Kind, description string) NativeDefinition {
	maxBytes := maxEnvironmentBytes
	if kind == Path {
		maxBytes = 4096
	}
	return NativeDefinition{
		Definition: Definition{
			Name: name, Kind: kind, Roles: API, MaxBytes: maxBytes,
			DefaultPolicy: "Optional native input; native defaults, fallback precedence and external resolution are separately owned.",
			Description:   description,
		},
		Boundary: boundary, Parameter: parameter, Source: source,
	}
}
