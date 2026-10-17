package config

// Configuration owns typed, role-specific input settings. Parse validates input
// without resolving external references. A value does not prove that files,
// credentials, database defaults or providers have been resolved or are ready.
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
}

// Parse applies role-specific defaults, syntax and local relationship checks to
// a captured environment. It consults no ambient environment, clock, files,
// network, listeners or provider loaders. Any failure returns zero settings.
// External reference/default resolution is a separate prerequisite to startup.
func Parse(environment Environment, role Role) (Configuration, error) {
	input, err := parseRoleInput(environment, role)
	if err != nil {
		return Configuration{}, err
	}
	return projectInput(input), nil
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
