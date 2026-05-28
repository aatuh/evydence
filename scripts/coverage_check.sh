#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

threshold="${EVYDENCE_COVERAGE_THRESHOLD:-80.0}"
profile="${EVYDENCE_COVERAGE_PROFILE:-coverage.out}"

go test ./... -coverprofile="$profile"

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
