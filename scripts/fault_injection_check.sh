#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
	printf '%s\n' "fault-injection-check: this command accepts no arguments" >&2
	exit 2
fi
if [ "${ENV:-}" = "production" ]; then
	printf '%s\n' "fault-injection-check: refusing to run with ENV=production" >&2
	exit 2
fi
if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
	printf '%s\n' "fault-injection-check: EVYDENCE_TEST_DATABASE_URL is required" >&2
	exit 2
fi
if [ -n "${EVYDENCE_DATABASE_URL:-}" ] && [ "$EVYDENCE_TEST_DATABASE_URL" = "$EVYDENCE_DATABASE_URL" ]; then
	printf '%s\n' "fault-injection-check: test and runtime database URLs must differ" >&2
	exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

# All fault injection is compiled only into Go test binaries. This gate covers
# application write-family decorators, live PostgreSQL pre-commit rollback,
# idempotency replay after response loss, object reconciliation kill points,
# and outbox restart fencing. It never starts an API or worker in fault mode.
go test ./internal/app -count=1
go test ./internal/adapters/postgres -count=1 -run '^(TestPostgresFailureAtomicityRollsBackEveryPreCommitPhase|TestPostgresUnitOfWorkCommitsAndRollsBackFocusedRepositoriesTogether|TestStoreCommitsIdempotentCommandAndReplayAtomically|TestRecoveryKillPointsFailClosedAndResume|TestApplyObjectReconciliationRollsBackLifecycleWhenReceiptInsertFails)$'
