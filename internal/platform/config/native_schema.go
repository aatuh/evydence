package config

import "slices"

// NativeBoundary identifies a separately owned driver/credential boundary.
// Declaring its inputs does not resolve defaults, files or provider credentials.
type NativeBoundary string

const NativePostgres NativeBoundary = "postgres"

// NativeDefinition extends the shared schema metadata with the native target
// parameter and pinned source. These inputs are not aliases for project options:
// a connection string can override PG* settings using native precedence.
type NativeDefinition struct {
	Definition
	Boundary  NativeBoundary
	Parameter string
	Source    string
}

var nativeInputDefinitions = nativePostgresDefinitions()

// NativeDefinitions returns owned, sorted native-input metadata. Like
// Definitions, it contains code-owned policy only, never operator values.
// Native parsing/resolution and command adoption remain separate steps.
func NativeDefinitions() []NativeDefinition {
	result := slices.Clone(nativeInputDefinitions)
	for i := range result {
		result[i].Allowed = slices.Clone(result[i].Allowed)
		result[i].ProductionAllowed = slices.Clone(result[i].ProductionAllowed)
		result[i].Aliases = slices.Clone(result[i].Aliases)
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
		if d.Name == name {
			return true
		}
	}
	return false
}
