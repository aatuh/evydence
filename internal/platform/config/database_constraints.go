package config

import (
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// These constrain explicit values; they do not copy driver defaults or perform
// native credential resolution. Unknown runtime GUCs remain driver/server owned.
var databaseSettingDefinitions = map[string]Definition{
	"connect_timeout":               {Kind: Seconds, Min: 0, Max: math.MaxInt64 / int64(time.Second)},
	"pool_max_conns":                {Kind: Integer, Min: 1, Max: math.MaxInt32},
	"pool_min_conns":                {Kind: Integer, Min: 0, Max: math.MaxInt32},
	"pool_min_idle_conns":           {Kind: Integer, Min: 0, Max: math.MaxInt32},
	"statement_cache_capacity":      {Kind: Integer, Min: 0, Max: math.MaxInt32},
	"description_cache_capacity":    {Kind: Integer, Min: 0, Max: math.MaxInt32},
	"pool_max_conn_lifetime":        {Kind: Duration, Min: 0, Max: math.MaxInt64},
	"pool_max_conn_idle_time":       {Kind: Duration, Min: 0, Max: math.MaxInt64},
	"pool_health_check_period":      {Kind: Duration, Min: 1, Max: math.MaxInt64},
	"pool_max_conn_lifetime_jitter": {Kind: Duration, Min: 0, Max: math.MaxInt64},
	"sslmode":                       {Kind: Choice, Allowed: []string{"", "disable", "allow", "prefer", "require", "verify-ca", "verify-full"}},
	"sslnegotiation":                {Kind: Choice, Allowed: []string{"", "postgres", "direct"}},
	"sslsni":                        {Kind: Choice, Allowed: []string{"", "0", "1"}},
	"target_session_attrs":          {Kind: Choice, Allowed: []string{"any", "read-write", "read-only", "primary", "standby", "prefer-standby"}},
	"channel_binding":               {Kind: Choice, Allowed: []string{"", "prefer", "disable", "require"}},
	"default_query_exec_mode":       {Kind: Choice, Allowed: []string{"cache_statement", "cache_describe", "describe_exec", "exec", "simple_protocol"}},
	"min_protocol_version":          {Kind: Choice, Allowed: []string{"", "3.0", "3.2", "latest"}},
	"max_protocol_version":          {Kind: Choice, Allowed: []string{"", "3.0", "3.2", "latest"}},
	"sslkey":                        {Kind: Path, MaxBytes: 4096},
	"sslcert":                       {Kind: Path, MaxBytes: 4096},
	"sslrootcert":                   {Kind: Path, MaxBytes: 4096},
	"passfile":                      {Kind: Path, MaxBytes: 4096},
	"servicefile":                   {Kind: Path, MaxBytes: 4096},
	"sslpassword":                   {Kind: Text, Secret: true},
}

func validateDatabaseSettings(values map[string]string) error {
	if err := validateDatabaseFields(values); err != nil {
		return err
	}
	return validateDatabaseRelationships(values, false)
}

func validateDatabaseFields(values map[string]string) error {
	for key, value := range values {
		if definition, known := databaseSettingDefinitions[key]; known {
			switch definition.Kind {
			case Integer, Seconds, Duration:
				// pgx/pgxpool parse these values without whitespace trimming.
				if value != strings.TrimSpace(value) {
					return ErrInvalidValue
				}
			}
			if definition.Kind == Choice {
				// Native PostgreSQL choices are case-sensitive.
				if !slices.Contains(definition.Allowed, value) {
					return ErrInvalidValue
				}
			} else if _, err := parseScalar(definition, value); err != nil {
				return err
			}
		} else if strings.HasPrefix(key, "pool_") || strings.HasPrefix(key, "ssl") {
			return ErrInvalidValue
		}
	}
	if host, exists := values["host"]; exists {
		if strings.Count(host, ",")+1 > maxDatabaseHosts {
			return ErrInvalidValue
		}
		for part := range strings.SplitSeq(host, ",") {
			if strings.HasPrefix(part, "/") {
				continue // Unix socket directories may contain spaces.
			}
			if strings.ContainsFunc(part, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				return ErrInvalidValue
			}
			if strings.Contains(part, ":") {
				if _, err := netip.ParseAddr(part); err != nil {
					return ErrInvalidValue
				}
			}
		}
	}
	if ports, exists := values["port"]; exists {
		if strings.Count(ports, ",")+1 > maxDatabaseHosts {
			return ErrInvalidValue
		}
		for port := range strings.SplitSeq(ports, ",") {
			if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
				return ErrInvalidValue
			}
		}
	}
	return nil
}

// allowIncomplete applies only while an explicitly selected service is still
// unresolved. Its settings can fill absent values beneath explicit DSN input.
func validateDatabaseRelationships(values map[string]string, allowIncomplete bool) error {
	if maximum, exists := values["pool_max_conns"]; exists {
		maximumCount, _ := strconv.ParseInt(maximum, 10, 32)
		for _, key := range []string{"pool_min_conns", "pool_min_idle_conns"} {
			if raw, present := values[key]; present {
				minimumCount, _ := strconv.ParseInt(raw, 10, 32)
				if minimumCount > maximumCount {
					return ErrInvalidValue
				}
			}
		}
	}
	_, certPresent := values["sslcert"]
	_, keyPresent := values["sslkey"]
	if (!allowIncomplete || (certPresent && keyPresent)) && (values["sslcert"] == "") != (values["sslkey"] == "") {
		return ErrInvalidValue
	}
	if (values["min_protocol_version"] == "3.2" || values["min_protocol_version"] == "latest") && values["max_protocol_version"] == "3.0" {
		return ErrInvalidValue
	}
	return nil
}
