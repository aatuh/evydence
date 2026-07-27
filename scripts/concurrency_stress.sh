#!/usr/bin/env sh
# Run deterministic idempotency ownership stress coverage. The default mirrors
# the EVY-303 CI repetition target; set a larger count for manual burn-in.
set -eu

iterations=${EVYDENCE_CONCURRENCY_STRESS_ITERATIONS:-10}
case "$iterations" in
  ''|*[!0-9]*)
    echo "EVYDENCE_CONCURRENCY_STRESS_ITERATIONS must be a positive integer" >&2
    exit 2
    ;;
esac
if [ "$iterations" -lt 1 ]; then
  echo "EVYDENCE_CONCURRENCY_STRESS_ITERATIONS must be a positive integer" >&2
  exit 2
fi

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  echo "EVYDENCE_TEST_DATABASE_URL is not set; PostgreSQL cross-instance coverage will be skipped." >&2
fi

go test -race \
  ./internal/app \
  ./internal/adapters/httpapi \
  ./internal/adapters/postgres \
  -run 'Test(WithIdempotency(Concurrent|Canceled|Recovers).*|CreateProductConcurrentIdempotencyRetriesOneStoredResponse|StoreConcurrentIdempotencyAcrossLedgerInstances)$' \
  -count="$iterations"
