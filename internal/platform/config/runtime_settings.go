package config

import "time"

// RuntimeSettings is a value copy. Slice accessors return owned copies.
// Formatting and JSON redact the entire settings value.
type RuntimeSettings struct {
	redactedValue
	Environment               string        `env:"ENV"`
	ConfigurationRevision     string        `env:"EVYDENCE_CONFIGURATION_REVISION"`
	ConfigurationRevisionFile string        `env:"EVYDENCE_CONFIGURATION_REVISION_FILE"`
	DatabaseURL               Secret        `env:"EVYDENCE_DATABASE_URL"`
	LogFormat                 string        `env:"EVYDENCE_LOG_FORMAT"`
	LogLevel                  string        `env:"EVYDENCE_LOG_LEVEL"`
	TracingEnabled            bool          `env:"EVYDENCE_TRACING_ENABLED"`
	TracingEndpoint           string        `env:"EVYDENCE_TRACING_ENDPOINT"`
	TracingSamplePerMillion   int64         `env:"EVYDENCE_TRACING_SAMPLE_PER_MILLION"`
	TracingQueueSize          int64         `env:"EVYDENCE_TRACING_QUEUE_SIZE"`
	TracingExportTimeout      time.Duration `env:"EVYDENCE_TRACING_EXPORT_TIMEOUT_SECONDS"`
	MigrationsDir             string        `env:"EVYDENCE_MIGRATIONS_DIR"`
	PostgresLoadMode          string        `env:"EVYDENCE_POSTGRES_LOAD_MODE"`
	Profile                   string        `env:"EVYDENCE_RUNTIME_PROFILE"`
	ShutdownCleanupTimeout    time.Duration `env:"EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS"`
	SkipMigrations            bool          `env:"EVYDENCE_SKIP_MIGRATIONS"`
}
