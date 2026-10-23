package config

func nativePostgresDefinitions() []NativeDefinition {
	var definitions []NativeDefinition
	for _, entry := range []struct{ name, parameter, description string }{
		{"PGHOST", "host", "Native comma-separated PostgreSQL hosts or Unix socket directories."},
		{"PGPORT", "port", "Native comma-separated PostgreSQL ports."},
		{"PGDATABASE", "database", "Native database name."},
		{"PGUSER", "user", "Native database user."},
		{"PGPASSWORD", "password", "Native database password; never diagnostic output."},
		{"PGPASSFILE", "passfile", "Native password-file reference; capture never opens it."},
		{"PGAPPNAME", "application_name", "Native PostgreSQL application name."},
		{"PGCONNECT_TIMEOUT", "connect_timeout", "Native connection timeout in seconds."},
		{"PGSSLMODE", "sslmode", "Native PostgreSQL TLS mode; values are case-sensitive."},
		{"PGSSLKEY", "sslkey", "Native client private-key file reference; capture never opens it."},
		{"PGSSLCERT", "sslcert", "Native client certificate file reference; capture never opens it."},
		{"PGSSLSNI", "sslsni", "Native TLS server-name-indication control, 0 or 1."},
		{"PGSSLROOTCERT", "sslrootcert", "Native TLS trust-root file reference; capture never opens it."},
		{"PGSSLPASSWORD", "sslpassword", "Native client-key password; never diagnostic output."},
		{"PGSSLNEGOTIATION", "sslnegotiation", "Native PostgreSQL TLS negotiation mode."},
		{"PGTARGETSESSIONATTRS", "target_session_attrs", "Native target-session selection policy."},
		{"PGSERVICE", "service", "Native service-file section name; resolution is a separate boundary."},
		{"PGSERVICEFILE", "servicefile", "Native service-file reference; capture never opens it."},
		{"PGTZ", "timezone", "Native PostgreSQL timezone setting."},
		{"PGOPTIONS", "options", "Native PostgreSQL startup options."},
		{"PGMINPROTOCOLVERSION", "min_protocol_version", "Native minimum PostgreSQL protocol version."},
		{"PGMAXPROTOCOLVERSION", "max_protocol_version", "Native maximum PostgreSQL protocol version."},
	} {
		// Share explicit-parameter types and constraints with the DSN grammar.
		// Native defaults and precedence are not applied during capture.
		d, known := databaseSettingDefinitions[entry.parameter]
		if !known {
			d.Kind = Text
		}
		if d.MaxBytes == 0 {
			d.MaxBytes = maxEnvironmentBytes
		}
		if entry.parameter == "host" || entry.parameter == "port" {
			d.MaxItems = maxDatabaseHosts
		}
		d.Name = entry.name
		d.Roles = databaseRoles
		d.Secret = entry.parameter == "password" || entry.parameter == "sslpassword"
		d.DefaultPolicy = "Optional native input beneath explicit connection parameters; driver defaults and file resolution are separate."
		d.Description = entry.description
		native := NativeDefinition{
			Definition:    d,
			Boundary:      NativePostgres,
			Parameter:     entry.parameter,
			Source:        "github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings",
			CaseSensitive: d.Kind == Choice,
			RejectControl: d.Kind == Path,
		}
		switch entry.parameter {
		case "host":
			native.Syntax, native.MaxItemBytes, native.RejectControl = NativePostgresHosts, 4096, true
		case "port":
			native.Syntax, native.MaxItemBytes = NativePostgresPorts, 4096
		}
		definitions = append(definitions, native)
	}
	return definitions
}
