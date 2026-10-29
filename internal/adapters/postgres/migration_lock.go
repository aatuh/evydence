package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
)

const migrationRunnerLockNamespace int32 = 0x6576796d

type migrationRunnerConnection struct {
	connection *pgxpool.Conn
	schema     string
	shared     bool
}

func (s *Store) acquireMigrationRunner(ctx context.Context) (*migrationRunnerConnection, error) {
	return s.acquireMigrationCoordinator(ctx, false)
}

func (s *Store) acquireMigrationStateReader(ctx context.Context) (*migrationRunnerConnection, error) {
	return s.acquireMigrationCoordinator(ctx, true)
}

func (s *Store) acquireMigrationCoordinator(ctx context.Context, shared bool) (*migrationRunnerConnection, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return nil, app.ErrValidation
	}
	connection, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	var schema string
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.current_schema()`).Scan(&schema); err != nil || schema == "" {
		discardMigrationConnection(ctx, connection)
		if err != nil {
			return nil, fmt.Errorf("resolve migration schema: %w", err)
		}
		return nil, errors.New("migration schema is unavailable")
	}
	// A session lock spans all per-file transactions and uses the same owned
	// connection for discovery, execution, tracking and eventual unlock.
	statement := `SELECT pg_catalog.pg_advisory_lock($1,pg_catalog.hashtext($2))`
	if shared {
		statement = `SELECT pg_catalog.pg_advisory_lock_shared($1,pg_catalog.hashtext($2))`
	}
	if _, err := connection.Exec(ctx, statement, migrationRunnerLockNamespace, schema); err != nil {
		// Acquisition may have reached the server before cancellation was seen.
		// An uncertain session must not be returned to the pool.
		discardMigrationConnection(ctx, connection)
		return nil, fmt.Errorf("acquire migration runner lock: %w", err)
	}
	return &migrationRunnerConnection{connection: connection, schema: schema, shared: shared}, nil
}

func discardMigrationConnection(ctx context.Context, connection *pgxpool.Conn) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = connection.Conn().Close(cleanup)
	connection.Release()
}

func (runner *migrationRunnerConnection) release(ctx context.Context) error {
	connection := runner.connection
	if connection.Conn().IsClosed() || connection.Conn().PgConn().TxStatus() != 'I' {
		discardMigrationConnection(ctx, connection)
		return errors.New("release migration connection failed")
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var released bool
	statement := `SELECT pg_catalog.pg_advisory_unlock($1,pg_catalog.hashtext($2))`
	if runner.shared {
		statement = `SELECT pg_catalog.pg_advisory_unlock_shared($1,pg_catalog.hashtext($2))`
	}
	if err := connection.QueryRow(cleanup, statement, migrationRunnerLockNamespace, runner.schema).Scan(&released); err != nil || !released {
		discardMigrationConnection(ctx, connection)
		return errors.New("release migration runner lock failed")
	}
	connection.Release()
	return nil
}
