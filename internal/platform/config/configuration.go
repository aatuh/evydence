package config

// Configuration owns typed, role-specific settings. Its constructor remains
// package-private until all dedicated validation is implemented; this type alone
// is not proof that an application's complete configuration has been validated.
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
