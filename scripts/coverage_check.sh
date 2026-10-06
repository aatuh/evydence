#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

threshold="${EVYDENCE_COVERAGE_THRESHOLD:-80.0}"
critical_threshold="${EVYDENCE_CRITICAL_COVERAGE_THRESHOLD:-81.0}"
profile="${EVYDENCE_COVERAGE_PROFILE:-coverage.out}"

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' "coverage-check: EVYDENCE_TEST_DATABASE_URL is required for the production coverage gate" >&2
  printf '%s\n' "coverage-check: use make coverage for local no-PostgreSQL coverage, or run make release-check-local-postgres" >&2
  exit 2
fi

go test ./... -coverpkg=./... -coverprofile="$profile" -timeout=30m

total="$(go tool cover -func="$profile" | awk '/^total:/ { gsub("%", "", $3); print $3 }')"
if [ -z "$total" ]; then
  printf '%s\n' "coverage-check: could not read total coverage" >&2
  exit 2
fi

awk -v got="$total" -v want="$threshold" 'BEGIN {
  if (got + 0 < want + 0) {
    printf "coverage-check: total coverage %.1f%% is below required %.1f%%\n", got, want > "/dev/stderr"
    exit 1
  }
  printf "coverage-check: total coverage %.1f%% meets required %.1f%%\n", got, want
}'

critical="$(awk '
  $1 ~ /^github[.]com\/aatuh\/evydence\/internal\/(app|domain|platform)\// ||
  $1 ~ /^github[.]com\/aatuh\/evydence\/internal\/adapters\/(httpapi|postgres|objectstore|verification)\// {
    # Cross-package profiles repeat blocks for distinct test binaries.
    # Match go tool cover: count each block once, covered by any execution.
    weights[$1] = $2
    if ($3 > 0) {
      executed[$1] = 1
    }
  }
  END {
    for (block in weights) {
      statements += weights[block]
      if (executed[block]) {
        covered += weights[block]
      }
    }
    if (statements == 0) {
      exit 2
    }
    printf "%.10f\n", covered * 100 / statements
  }
' "$profile")" || {
  printf '%s\n' "coverage-check: could not read critical-package coverage" >&2
  exit 2
}

awk -v got="$critical" -v want="$critical_threshold" 'BEGIN {
  if (got + 0 < want + 0) {
    printf "coverage-check: critical-package coverage %.1f%% is below required %.1f%%\n", got, want > "/dev/stderr"
    exit 1
  }
  printf "coverage-check: critical-package coverage %.1f%% meets required %.1f%%\n", got, want
}'
