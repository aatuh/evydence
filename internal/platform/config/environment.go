package config

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxEnvironmentEntries = 4096
	maxEnvironmentBytes   = 8 << 20
	maxSelectedSettings   = 1024
	maxEnvironmentName    = 256
)

// ErrInvalidEnvironment deliberately carries no supplied name, value or cause.
var ErrInvalidEnvironment = errors.New("invalid runtime configuration input")

// Environment owns a bounded snapshot. Values are available only to this
// package's parsers; callers cannot mutate or accidentally format the map.
type Environment struct {
	values      map[string]string
	fingerprint [32]byte
}

// Capture reads only the supplied entries. It preserves raw values and explicit
// emptiness for field-specific validation and never consults the process env.
// All failures return an empty object rather than partially captured secrets.
func Capture(entries []string) (Environment, error) {
	if len(entries) > maxEnvironmentEntries {
		return Environment{}, ErrInvalidEnvironment
	}
	e := Environment{values: make(map[string]string, min(len(entries), maxSelectedSettings))}
	bytes := 0
	for _, entry := range entries {
		if len(entry) > maxEnvironmentBytes-bytes {
			return Environment{}, ErrInvalidEnvironment
		}
		bytes += len(entry)
		name, value, found := strings.Cut(entry, "=")
		if !selectedEnvironmentName(name) {
			continue
		}
		if !found || !validEnvironmentName(name) || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return Environment{}, ErrInvalidEnvironment
		}
		if _, duplicate := e.values[name]; duplicate || len(e.values) >= maxSelectedSettings {
			return Environment{}, ErrInvalidEnvironment
		}
		e.values[name] = value
	}

	h := sha256.New()
	_, _ = h.Write([]byte("evydence-configuration-input.v1\x00"))
	for _, name := range e.names() {
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(e.values[name]))
		_, _ = h.Write([]byte{0})
	}
	copy(e.fingerprint[:], h.Sum(nil))
	return e, nil
}

func selectedEnvironmentName(name string) bool {
	return name == "ENV" || name == "CI" || strings.HasPrefix(name, "EVYDENCE_") ||
		strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "GOOGLE_") ||
		strings.HasPrefix(name, "AZURE_") || strings.HasPrefix(name, "GITHUB_") ||
		nativeEnvironmentName(name)
}

func validEnvironmentName(name string) bool {
	if len(name) == 0 || len(name) > maxEnvironmentName {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (e Environment) lookup(name string) (string, bool) {
	value, ok := e.values[name]
	return value, ok
}

func (e Environment) names() []string {
	names := make([]string, 0, len(e.values))
	for name := range e.values {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (Environment) String() string   { return "config.Environment{redacted}" }
func (Environment) GoString() string { return "config.Environment{redacted}" }
func (Environment) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}
