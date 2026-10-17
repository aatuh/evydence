package config

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidSecretReference   = errors.New("invalid secret reference input")
	ErrConflictingSecretSources = errors.New("conflicting secret input sources")
)

// secretFileReference is a private, owned plan; it carries no resolved contents.
// Default formatting must hide operator paths as well as credential values.
type secretFileReference struct {
	redactedValue
	target     string
	fileOption string
	path       string
	maxBytes   int
}

// parseSecretReferences validates declarations only, without opening a path or
// resolving a credential. Public input/resolution composition remains separate.
func parseSecretReferences(environment Environment, role Role) ([]secretFileReference, error) {
	if role != API && role != Worker && role != Migrate && role != CLI {
		return nil, ErrInvalidRole
	}
	var refs []secretFileReference
	for _, d := range Definitions() {
		if d.Roles&role == 0 || d.FileOption == "" {
			continue
		}
		path, _ := environment.lookup(d.FileOption)
		if path == "" {
			continue // An explicitly empty file alternative remains unset.
		}
		for _, name := range append([]string{d.Name}, d.Aliases...) {
			if raw, _ := environment.lookup(name); raw != "" {
				return nil, ErrConflictingSecretSources
			}
		}
		if !validSecretReferencePath(path) {
			return nil, ErrInvalidSecretReference
		}
		maxBytes := d.MaxBytes
		if maxBytes <= 0 || maxBytes > maxEnvironmentBytes {
			maxBytes = maxEnvironmentBytes
		}
		refs = append(refs, secretFileReference{target: d.Name, fileOption: d.FileOption, path: path, maxBytes: maxBytes})
	}
	return refs, nil
}

func validSecretReferencePath(path string) bool {
	return len(path) <= 4096 && utf8.ValidString(path) && path == strings.TrimSpace(path) &&
		!strings.ContainsFunc(path, unicode.IsControl) && filepath.IsAbs(path) && filepath.Clean(path) == path
}
