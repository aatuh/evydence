#!/bin/sh
set -eu

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  echo "restore rehearsal requires EVYDENCE_TEST_DATABASE_URL; memory fallback is not allowed" >&2
  exit 2
fi

for tool in pg_dump pg_restore python3 git "${GO:-go}"; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "restore rehearsal requires tool: $tool" >&2
    exit 2
  }
done

PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_paired_backup_manifest.py
"${GO:-go}" test ./internal/adapters/postgres \
  -run '^TestPostgresBackupRestoreRehearsalPreservesLedgerAndObjects(PairedNative)?$' \
  -count=1 -v
