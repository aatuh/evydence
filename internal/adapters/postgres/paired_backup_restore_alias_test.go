package postgres

import "testing"

// This suffixed name is intentionally selected by the existing
// `make restore-rehearsal-check` -run expression, so that repository-owned
// recovery validation includes the native pg_dump/pg_restore rehearsal without
// duplicating the implementation.
func TestPostgresBackupRestoreRehearsalPreservesLedgerAndObjectsPairedNative(t *testing.T) {
	TestPostgresPairedBackupRestoreUsesNativeDumpAndFilesystemGeneration(t)
}
