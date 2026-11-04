package postgres

import (
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/platform/logging"
)

//go:embed runtime_role.sql
var runtimeRolePolicySQL string

var (
	ErrMigrationRuntimeRole     = errors.New("migration runtime role policy failed")
	ErrMigrationOperation       = errors.New("migration operation record failed")
	ErrMigrationRuntimeNotReady = errors.New("managed migration is not ready for this runtime")
)

const migrationOperationSchemaVersion = "migration-operation.v1"

const migrationOperationSchemaSQL = `CREATE TABLE IF NOT EXISTS %s (
 sequence bigint PRIMARY KEY CHECK (sequence > 0),
 operation_id text NOT NULL,
 phase text NOT NULL CHECK (phase IN ('started','succeeded','failed','uncertain')),
 target_version text NOT NULL,
 runtime_role name NOT NULL,
 performed_by name NOT NULL DEFAULT session_user,
 committed_migrations integer CHECK (committed_migrations >= 0),
 policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 schema_version text NOT NULL DEFAULT 'migration-operation.v1',
 CHECK ((phase = 'uncertain') = (committed_migrations IS NULL)),
 UNIQUE (operation_id,phase)
)`

func validMigrationRuntimeRole(role string) bool {
	return role != "" && len(role) <= 63 && utf8.ValidString(role) && strings.TrimSpace(role) != "" && !strings.ContainsFunc(role, unicode.IsControl)
}

// A single execution owns one coordinator session and one lazily started
// cleanup budget. Rollback, terminal audit and unlock never renew that budget.
type migrationExecution struct {
	runner                        *migrationRunnerConnection
	runtimeRole                   string
	target                        string
	operationID                   string
	started, completed, uncertain bool
	cleanup                       context.Context
	cancel                        context.CancelFunc
}

func (e *migrationExecution) cleanupContext(ctx context.Context) context.Context {
	if e.cleanup == nil {
		e.cleanup, e.cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	}
	return e.cleanup
}

func (e *migrationExecution) rollback(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(e.cleanupContext(ctx))
}

func migrationOperationError(kind, err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.Join(kind, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(kind, context.DeadlineExceeded)
	}
	return kind
}

func (e *migrationExecution) policy(ctx context.Context, tx pgx.Tx, phase string) error {
	_, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('search_path',$1,true),pg_catalog.set_config('evydence.runtime_role',$2,true),pg_catalog.set_config('evydence.runtime_role_phase',$3,true)`, pgx.Identifier{e.runner.schema}.Sanitize(), e.runtimeRole, phase)
	if err == nil {
		_, err = tx.Exec(ctx, runtimeRolePolicySQL)
	}
	if err != nil {
		return migrationOperationError(ErrMigrationRuntimeRole, err)
	}
	return nil
}

func (e *migrationExecution) validate(ctx context.Context) error {
	if e.runtimeRole == "" {
		table := pgx.Identifier{e.runner.schema, "schema_migration_operations"}.Sanitize()
		var exists bool
		if err := e.runner.connection.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			return migrationOperationError(ErrMigrationRuntimeRole, err)
		}
		if exists {
			var activated bool
			if err := e.runner.connection.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s)`, table)).Scan(&activated); err != nil {
				return migrationOperationError(ErrMigrationRuntimeRole, err)
			}
			if activated {
				return ErrMigrationRuntimeRole
			}
		}
		return nil
	}
	tx, err := e.runner.connection.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return migrationOperationError(ErrMigrationRuntimeRole, err)
	}
	if err = e.policy(ctx, tx, "validate"); err != nil {
		e.rollback(ctx, tx)
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return migrationOperationError(ErrMigrationRuntimeRole, err)
	}
	return nil
}

type migrationOperationWriter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func (e *migrationExecution) append(ctx context.Context, writer migrationOperationWriter, phase string, count *int) error {
	table := pgx.Identifier{e.runner.schema, "schema_migration_operations"}.Sanitize()
	// The exclusive coordinator serializes appenders. MAX uses the primary-key
	// index; callers cannot supply sequence values or authenticated principals.
	statement := fmt.Sprintf(`INSERT INTO %s(sequence,operation_id,phase,target_version,runtime_role,performed_by,committed_migrations,policy_sha256,schema_version)VALUES((SELECT COALESCE(MAX(sequence),0)+1 FROM %s),$1,$2,$3,$4,session_user,$5,$6,$7)`, table, table)
	_, err := writer.Exec(ctx, statement, e.operationID, phase, e.target, e.runtimeRole, count, migrationChecksum(runtimeRolePolicySQL), migrationOperationSchemaVersion)
	if err != nil {
		return migrationOperationError(ErrMigrationOperation, err)
	}
	return nil
}

func (e *migrationExecution) start(ctx context.Context) error {
	if e.runtimeRole == "" {
		return nil
	}
	table := pgx.Identifier{e.runner.schema, "schema_migration_operations"}.Sanitize()
	if _, err := e.runner.connection.Exec(ctx, fmt.Sprintf(migrationOperationSchemaSQL, table)); err != nil {
		return migrationOperationError(ErrMigrationOperation, err)
	}
	e.operationID = "mop_" + rand.Text()
	tx, err := e.runner.connection.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return migrationOperationError(ErrMigrationOperation, err)
	}
	if err = e.policy(ctx, tx, "grant"); err != nil {
		e.rollback(ctx, tx)
		return err
	}
	zero := 0
	if err = e.append(ctx, tx, "started", &zero); err != nil {
		e.rollback(ctx, tx)
		return err
	}
	e.started = true
	if err = tx.Commit(ctx); err != nil {
		e.uncertain = true
		return migrationOperationError(ErrMigrationOperation, err)
	}
	logging.Emit(ctx, logging.Audit, logging.Fields{OperationID: e.operationID, Result: logging.Started})
	return nil
}

func (e *migrationExecution) complete(ctx context.Context, count int) error {
	if e.runtimeRole == "" {
		return nil
	}
	tx, err := e.runner.connection.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return migrationOperationError(ErrMigrationOperation, err)
	}
	if err = e.policy(ctx, tx, "grant"); err != nil {
		e.rollback(ctx, tx)
		return err
	}
	if err = e.append(ctx, tx, "succeeded", &count); err != nil {
		e.rollback(ctx, tx)
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		e.uncertain = true
		return migrationOperationError(ErrMigrationOperation, err)
	}
	e.completed = true
	logging.Emit(ctx, logging.Audit, logging.Fields{OperationID: e.operationID, Result: logging.Succeeded})
	return nil
}

func (e *migrationExecution) close(ctx context.Context, workErr error, count int) error {
	cleanup := e.cleanupContext(ctx)
	defer e.cancel()
	var auditErr error
	if e.started && !e.completed {
		phase, committed := "failed", &count
		if e.uncertain {
			phase, committed = "uncertain", nil
		}
		auditErr = e.append(cleanup, e.runner.connection, phase, committed)
		result := logging.Failed
		if e.uncertain || auditErr != nil {
			result = logging.Uncertain
		}
		logging.Emit(cleanup, logging.Audit, logging.Fields{OperationID: e.operationID, Result: result})
		if workErr == nil {
			auditErr = errors.Join(auditErr, ErrMigrationOperation)
		}
	}
	return errors.Join(auditErr, e.runner.releaseWithin(cleanup))
}

func (reader *migrationRunnerConnection) checkMigrationOperationReady(ctx context.Context, target string) error {
	table := pgx.Identifier{reader.schema, "schema_migration_operations"}.Sanitize()
	var exists bool
	if err := reader.connection.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return migrationOperationError(ErrMigrationRuntimeNotReady, err)
	}
	if !exists {
		return nil
	}
	history := pgx.Identifier{reader.schema, "schema_migrations"}.Sanitize()
	statement := fmt.Sprintf(`SELECT phase='succeeded' AND runtime_role=session_user AND schema_version=$1 AND policy_sha256=$2 AND target_version=$6
 AND NOT pg_catalog.has_schema_privilege(session_user,$3::text,'CREATE')
 AND NOT pg_catalog.has_table_privilege(session_user,$4::text,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT pg_catalog.has_any_column_privilege(session_user,$4::text,'INSERT,UPDATE,REFERENCES')
 AND NOT pg_catalog.has_table_privilege(session_user,$5::text,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT pg_catalog.has_any_column_privilege(session_user,$5::text,'INSERT,UPDATE,REFERENCES')
 FROM %s ORDER BY sequence DESC LIMIT 1`, table)
	var ready bool
	err := reader.connection.QueryRow(ctx, statement, migrationOperationSchemaVersion, migrationChecksum(runtimeRolePolicySQL), reader.schema, table, history, target).Scan(&ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return migrationOperationError(ErrMigrationRuntimeNotReady, err)
	}
	if !ready {
		return ErrMigrationRuntimeNotReady
	}
	return nil
}
