package config

import "crypto/sha256"

// Configuration owns typed, role-specific input settings. Parse validates inline
// input; Resolve also materializes active project-secret file alternatives.
// Neither proves that native credentials, database defaults or providers are ready.
type Configuration struct {
	redactedValue
	role       Role
	production bool
	runtime    RuntimeSettings
	api        APISettings
	worker     WorkerSettings
	storage    StorageSettings
	providers  ProviderSettings
	cli        CLISettings
	native     NativeSettings
	database   databaseInput

	workerMetricsHash    [sha256.Size]byte
	workerMetricsEnabled bool
}

// Parse applies role-specific defaults, syntax and local relationship checks to
// a captured environment. It consults no ambient environment, clock, files,
// network, listeners or provider loaders. Any failure returns zero settings.
// Applicable file alternatives require Prepare followed by explicit Resolve.
// Native reference/default resolution is a separate prerequisite to startup.
func Parse(environment Environment, role Role) (Configuration, error) {
	input, err := Prepare(environment, role)
	if err != nil {
		return Configuration{}, err
	}
	if len(input.references) != 0 {
		return Configuration{}, ErrUnresolvedSecretReference
	}
	return projectInput(input.parsed), nil
}

func (c Configuration) Role() Role                  { return c.role }
func (c Configuration) Production() bool            { return c.production }
func (c Configuration) Runtime() RuntimeSettings    { return c.runtime }
func (c Configuration) API() APISettings            { return c.api }
func (c Configuration) Worker() WorkerSettings      { return c.worker }
func (c Configuration) Storage() StorageSettings    { return c.storage }
func (c Configuration) Providers() ProviderSettings { return c.providers }
func (c Configuration) CLI() CLISettings            { return c.cli }
func (c Configuration) Native() NativeSettings      { return c.native }

// WorkerMetricsTokenHash returns an owned digest only after explicit successful
// resolution of the metrics credential. Parse alone never enables this result.
func (c Configuration) WorkerMetricsTokenHash() ([sha256.Size]byte, bool) {
	return c.workerMetricsHash, c.workerMetricsEnabled
}

// Secret permits deliberate value access at an adapter boundary while keeping
// ordinary formatting and JSON safe. The zero value is an absent credential.
type Secret struct {
	redactedValue
	value string
}

func (s Secret) Reveal() string { return s.value }
func (s Secret) IsSet() bool    { return s.value != "" }

type redactedValue struct{}

func (redactedValue) String() string   { return "config.Value{redacted}" }
func (redactedValue) GoString() string { return "config.Value{redacted}" }
func (redactedValue) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}
