package config

import (
	"strconv"
	"time"
)

var runtimeDefinitions = []Definition{
	{
		Name:        "ENV",
		Kind:        Choice,
		Roles:       AllRoles,
		Allowed:     []string{"", "development", "staging", "production", "test", "local"},
		Description: "Production-safety selector. Unset retains the non-production development profile.",
	},
	{
		Name:               "EVYDENCE_CONFIGURATION_REVISION",
		PreserveWhitespace: true,
		Kind:               Text,
		Roles:              API | Worker,
		Description:        "API/worker configuration revision: exactly 64 lowercase hexadecimal characters. Must match the projected revision file at startup and on subsequent cached health refreshes. This is an operator revision identifier, not evidence or a secret digest.",
	},
	{
		Name:               "EVYDENCE_CONFIGURATION_REVISION_FILE",
		PreserveWhitespace: true,
		Kind:               Path,
		Roles:              API | Worker,
		MaxBytes:           4096,
		Description:        "Absolute path to an operator-owned local regular file containing the desired revision (at most 256 bytes, surrounding whitespace allowed). Symlinked projections must resolve inside the configured parent directory. Missing, invalid or changed content fails startup/readiness; no hot reload. See [configuration freshness](observability.md#configuration-freshness).",
	},
	{
		Name:        "EVYDENCE_DATABASE_URL",
		FileOption:  "EVYDENCE_DATABASE_URL_FILE",
		Kind:        PostgresDSN,
		Roles:       databaseRoles,
		Secret:      true,
		Required:    databaseRoles,
		Description: "PostgreSQL durable state, projections, migrations, and persisted outbox jobs. Connection settings alone do not select the runtime profile.",
	},
	{
		Name:        "EVYDENCE_LOG_FORMAT",
		Kind:        Choice,
		Roles:       AllRoles,
		Default:     "json",
		Allowed:     []string{"json", "text"},
		Description: "`json` or `text` (case-insensitive); both retain the same structured fields. Logs go to stderr; command results and explicitly requested local bootstrap credentials retain their separate stdout contract.",
	},
	{
		Name:        "EVYDENCE_LOG_LEVEL",
		Kind:        Choice,
		Roles:       AllRoles,
		Default:     "info",
		Allowed:     []string{"debug", "info", "warn", "error"},
		Description: "API, worker and migration diagnostics: `debug`, `info`, `warn`, `error` (case-insensitive). Invalid values fail before dependency startup.",
	},
	{
		Name:        "EVYDENCE_MIGRATIONS_DIR",
		Kind:        Path,
		MaxBytes:    4096,
		Roles:       databaseRoles,
		Default:     "migrations",
		Description: "Migration directory for API startup and `cmd/evydence-migrate`.",
	},
	{
		Name:                 "EVYDENCE_POSTGRES_LOAD_MODE",
		Kind:                 Choice,
		Roles:                runtimeRoles,
		DefaultPolicy:        "relational_only in production; snapshot_preferred outside production",
		ProductionDefault:    "relational_only",
		NonProductionDefault: "snapshot_preferred",
		Allowed:              []string{"", "snapshot", "snapshot_preferred", "snapshot-preferred", "relational", "relational_preferred", "relational-preferred", "relational_only", "relational-only"},
		ProductionAllowed:    []string{"", "relational_only", "relational-only"},
		Description:          "PostgreSQL state load mode. Supported values are `snapshot_preferred`, `relational_preferred`, and `relational_only`. Production defaults to relational-only startup reads, refuses snapshot fallback modes, and disables compatibility snapshot writes; snapshots remain available for local compatibility and non-production migration checks.",
	},
	{
		Name:        "EVYDENCE_RUNTIME_PROFILE",
		Kind:        Choice,
		Roles:       runtimeRoles,
		Required:    runtimeRoles,
		Allowed:     []string{"postgres"},
		Description: "The only supported runtime profile, including local evaluation. Retired `local_memory` input fails before opening resources and explains the PostgreSQL migration.",
	},
	{
		Name:        "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS",
		Kind:        Seconds,
		Roles:       databaseRoles,
		Default:     strconv.FormatInt(int64(DefaultCleanupTimeout/time.Second), 10),
		Min:         int64(MinCleanupTimeout / time.Second),
		Max:         int64(MaxCleanupTimeout / time.Second),
		Description: "API/worker resource-cleanup budget after draining or operator-command execution; whole seconds from 1 through 60. Invalid values fail before storage opens.",
	},
	{
		Name:        "EVYDENCE_SKIP_MIGRATIONS",
		Kind:        Boolean,
		Roles:       runtimeRoles,
		Default:     "false",
		Description: "Set to `true` only when migrations are applied by a separate release process. API and worker startup still verify that no committed migrations are pending and fail closed if the database is behind.",
	},
}
