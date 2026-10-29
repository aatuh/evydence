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
}

func (s *Store) acquireMigrationRunner(ctx context.Context) (*migrationRunnerConnection, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return nil, app.ErrValidation
	}
	connection, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	var schema string
	if err := connection.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil || schema == "" {
		discardMigrationConnection(ctx, connection)
		if err != nil {
			return nil, fmt.Errorf("resolve migration schema: %w", err)
		}
		return nil, errors.New("migration schema is unavailable")
	}
	// A session lock spans all per-file transactions and uses the same owned
	// connection for discovery, execution, tracking and eventual unlock.
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock($1,hashtext($2))`, migrationRunnerLockNamespace, schema); err != nil {
		// Acquisition may have reached the server before cancellation was seen.
		// An uncertain session must not be returned to the pool.
		discardMigrationConnection(ctx, connection)
		return nil, fmt.Errorf("acquire migration runner lock: %w", err)
	}
	return &migrationRunnerConnection{connection: connection, schema: schema}, nil
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
	if err := connection.QueryRow(cleanup, `SELECT pg_advisory_unlock($1,hashtext($2))`, migrationRunnerLockNamespace, runner.schema).Scan(&released); err != nil || !released {
		discardMigrationConnection(ctx, connection)
		return errors.New("release migration runner lock failed")
	}
	connection.Release()
	return nil
}
