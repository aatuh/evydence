package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidConfiguration = errors.New("invalid PostgreSQL pool configuration")

// PreparedPoolConfig owns resolved native driver settings without any open
// connections. Its fields and formatting keep credentials and paths private.
// Copies can open independent pools; each open copies the driver configuration.
type PreparedPoolConfig struct {
	config *pgxpool.Config
}

func (PreparedPoolConfig) String() string   { return "postgres.PreparedPoolConfig{redacted}" }
func (PreparedPoolConfig) GoString() string { return "postgres.PreparedPoolConfig{redacted}" }
func (PreparedPoolConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

func (c PreparedPoolConfig) IsPrepared() bool { return c.config != nil }

// Matches checks the explicit input without exposing the stored connection
// string. Native service/password/TLS settings are already resolved at this point.
func (c PreparedPoolConfig) Matches(databaseURL string) bool {
	return c.config != nil && c.config.ConnConfig.ConnString() == databaseURL
}

// PreparePoolConfig enters the pinned pgx native resolution boundary exactly
// once, before any dial, pool maintenance, migrations or runtime resource opens.
// pgx owns native environment, service/pass/TLS-file and OS-default policies;
// this is not the bounded project-secret reader. Its synchronous parser has no
// context API, so cancellation is checked before and after, without detached I/O.
func PreparePoolConfig(ctx context.Context, databaseURL string) (PreparedPoolConfig, error) {
	if ctx == nil {
		return PreparedPoolConfig{}, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return PreparedPoolConfig{}, err
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil || !validPreparedPoolConfig(config) {
		return PreparedPoolConfig{}, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return PreparedPoolConfig{}, err
	}
	return PreparedPoolConfig{config: config}, nil
}

// Native service files can supply values not seen by pure project preflight.
// pgx accepts some structurally unsafe pool settings; reject them before its
// background pool constructor, which requires positive health periods and
// usable connection/maintenance bounds. This supplies no driver defaults.
func validPreparedPoolConfig(config *pgxpool.Config) bool {
	if config == nil || config.ConnConfig == nil || config.ConnConfig.Port == 0 || config.ConnConfig.ConnectTimeout < 0 ||
		config.MaxConns < 1 || config.MinConns < 0 || config.MinIdleConns < 0 ||
		config.MinConns > config.MaxConns || config.MinIdleConns > config.MaxConns ||
		config.MaxConnLifetime < 0 || config.MaxConnIdleTime < 0 || config.MaxConnLifetimeJitter < 0 || config.HealthCheckPeriod <= 0 {
		return false
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback == nil || fallback.Port == 0 {
			return false
		}
	}
	return true
}
