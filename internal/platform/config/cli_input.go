package config

import (
	"errors"
	"maps"
)

// CLICommand selects applicable online inputs. Offline/help commands do not
// prepare runtime configuration. These bits are schema metadata, not identities
// or proof that a CI provider's claims have been verified.
type CLICommand uint8

const (
	CLIUpload CLICommand = 1 << iota
	CLIGitHubBuild
	CLIPreflight
	allCLICommands = CLIUpload | CLIGitHubBuild | CLIPreflight
)

var ErrInvalidCLICommand = errors.New("invalid CLI configuration command or flag")

// PrepareCLI applies explicit, schema-bound flags to an owned snapshot and
// excludes inputs unused by this command. It performs no file or network I/O.
// Flags override inline environment defaults, including an explicit empty flag.
// A credential flag never silently overrides a declared secret-file source.
// Resolve must still materialize active private files before using settings.
func PrepareCLI(environment Environment, command CLICommand, flags map[string]string) (PreparedInput, error) {
	if command == 0 || command&^allCLICommands != 0 || command&(command-1) != 0 {
		return PreparedInput{}, ErrInvalidCLICommand
	}
	values := maps.Clone(environment.values)
	if values == nil {
		values = make(map[string]string)
	}
	bindings := make(map[string]Definition)
	for _, d := range Definitions() {
		if d.Roles&CLI == 0 {
			continue
		}
		if d.CLICommands != 0 && d.CLICommands&command == 0 {
			delete(values, d.Name)
			delete(values, d.FileOption)
			for _, alias := range d.Aliases {
				delete(values, alias)
			}
			continue
		}
		if d.CLIFlag != "" {
			bindings[d.CLIFlag] = d
		}
	}
	for flag, value := range flags {
		d, ok := bindings[flag]
		if !ok {
			return PreparedInput{}, ErrInvalidCLICommand
		}
		if d.FileOption != "" && values[d.FileOption] != "" {
			return PreparedInput{}, ErrConflictingSecretSources
		}
		values[d.Name] = value
	}
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	effective, err := Capture(entries)
	if err != nil {
		return PreparedInput{}, err
	}
	return Prepare(effective, CLI)
}
