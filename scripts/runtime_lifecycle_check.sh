#!/usr/bin/env sh
set -eu
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' 'runtime-lifecycle-check: EVYDENCE_TEST_DATABASE_URL is required' >&2
  exit 2
fi
for binary in "${EVYDENCE_LIFECYCLE_API_BIN:-}" "${EVYDENCE_LIFECYCLE_WORKER_BIN:-}"; do
  if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    printf '%s\n' 'runtime-lifecycle-check: both release binary paths are required' >&2
    exit 2
  fi
done
api="$EVYDENCE_LIFECYCLE_API_BIN"
worker="$EVYDENCE_LIFECYCLE_WORKER_BIN"
case "$api" in /*) ;; *) api="$repo_root/$api";; esac
case "$worker" in /*) ;; *) worker="$repo_root/$worker";; esac
export EVYDENCE_LIFECYCLE_API_BIN="$api" EVYDENCE_LIFECYCLE_WORKER_BIN="$worker"
directory="${EVYDENCE_LIFECYCLE_ARTIFACT_DIR:-tmp/runtime-lifecycle}"
case "$directory" in tmp/*) ;; *) printf '%s\n' 'runtime-lifecycle-check: artifact directory must stay under tmp/' >&2; exit 2;; esac
case "$directory" in *..*|*/.*) printf '%s\n' 'runtime-lifecycle-check: artifact dot segments are forbidden' >&2; exit 2;; esac
python3 - "$directory" <<'PY'
from pathlib import Path
import sys
directory=Path(sys.argv[1])
for prefix in (directory,*directory.parents):
    if prefix.is_symlink():
        raise SystemExit('runtime-lifecycle-check: artifact path must not contain symlinks')
PY
# Refuse existing artifacts, including symlinks, rather than erase prior proof.
mkdir -m 700 "$directory"
export EVYDENCE_LIFECYCLE_ARTIFACT_DIR="$repo_root/$directory"
EVYDENCE_LIFECYCLE_EXPECTED_COMMIT="${EVYDENCE_LIFECYCLE_EXPECTED_COMMIT:-$(git rev-parse HEAD)}"
export EVYDENCE_LIFECYCLE_EXPECTED_COMMIT
set +e
go test -tags=releasebinary ./internal/platform/lifecyclecheck -json -count=1 -timeout=3m >"$directory/events.jsonl" 2>"$directory/go.stderr"
code=$?
set -e
python3 scripts/runtime_lifecycle_evidence.py "$directory" "$code"
