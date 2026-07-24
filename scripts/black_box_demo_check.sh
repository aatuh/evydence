#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' "black-box-demo-check: EVYDENCE_TEST_DATABASE_URL is required" >&2
  exit 2
fi

for tool in curl go jq psql python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "black-box-demo-check: missing required tool: $tool" >&2
    exit 2
  fi
done

workdir="${EVYDENCE_BLACK_BOX_WORKDIR:-tmp/black-box-demo-check}"
schema="demo_schema_$(date +%s)_$$"
api_pid=""
worker_pid=""

cleanup() {
  if [ -n "$api_pid" ] && kill -0 "$api_pid" >/dev/null 2>&1; then
    kill "$api_pid" >/dev/null 2>&1 || true
    wait "$api_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$worker_pid" ] && kill -0 "$worker_pid" >/dev/null 2>&1; then
    kill "$worker_pid" >/dev/null 2>&1 || true
    wait "$worker_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$schema" ]; then
    psql "$EVYDENCE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
  fi
  if [ "${EVYDENCE_BLACK_BOX_KEEP_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$workdir"
  fi
}
trap cleanup EXIT INT TERM

rm -rf "$workdir"
mkdir -p "$workdir"/objects "$workdir"/demo

printf '%s\n' "black-box-demo-check: preparing disposable schema $schema"
psql "$EVYDENCE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q -c "CREATE SCHEMA $schema" >/dev/null

database_url="$(python3 - "$EVYDENCE_TEST_DATABASE_URL" "$schema" <<'PY'
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

base_url, schema = sys.argv[1], sys.argv[2]
parts = urlsplit(base_url)
query = dict(parse_qsl(parts.query, keep_blank_values=True))
query["search_path"] = schema
print(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)))
PY
)"

port="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
api_url="http://127.0.0.1:$port"

prepare_binary() {
  env_name="$1"
  fallback_pkg="$2"
  output="$3"
  case "$env_name" in
    EVYDENCE_BLACK_BOX_API_BIN) configured="${EVYDENCE_BLACK_BOX_API_BIN:-}" ;;
    EVYDENCE_BLACK_BOX_WORKER_BIN) configured="${EVYDENCE_BLACK_BOX_WORKER_BIN:-}" ;;
    *)
      printf '%s\n' "black-box-demo-check: unsupported binary env selector" >&2
      exit 2
      ;;
  esac
  if [ -n "$configured" ]; then
    if [ ! -x "$configured" ]; then
      printf '%s\n' "black-box-demo-check: $env_name must point to an executable file" >&2
      exit 2
    fi
    cp "$configured" "$output"
  else
    go build -o "$output" "$fallback_pkg"
  fi
}

prepare_binary EVYDENCE_BLACK_BOX_API_BIN ./cmd/evydence-api "$workdir/evydence-api"
prepare_binary EVYDENCE_BLACK_BOX_WORKER_BIN ./cmd/evydence-worker "$workdir/evydence-worker"

start_api() {
  label="$1"
  print_secret="$2"
  stdout="$workdir/api-$label.stdout"
  stderr="$workdir/api-$label.stderr"
  EVYDENCE_ADDR="127.0.0.1:$port" \
  EVYDENCE_DATABASE_URL="$database_url" \
  EVYDENCE_POSTGRES_LOAD_MODE=relational_only \
  EVYDENCE_API_KEY_PEPPER="black-box-demo-pepper" \
  EVYDENCE_OBJECT_STORE=filesystem \
  EVYDENCE_OBJECT_DIR="$workdir/objects" \
  EVYDENCE_BOOTSTRAP_TENANT="Black Box Demo Tenant" \
  EVYDENCE_PRINT_BOOTSTRAP_SECRET="$print_secret" \
  "$workdir/evydence-api" >"$stdout" 2>"$stderr" &
  api_pid="$!"
  for _ in $(seq 1 80); do
    if curl -fsS "$api_url/v1/ready" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$api_pid" >/dev/null 2>&1; then
      printf '%s\n' "black-box-demo-check: API process exited during $label startup" >&2
      sed -n '1,120p' "$stderr" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  printf '%s\n' "black-box-demo-check: API did not become ready during $label startup" >&2
  sed -n '1,120p' "$stderr" >&2 || true
  return 1
}

start_worker() {
  EVYDENCE_DATABASE_URL="$database_url" \
  EVYDENCE_POSTGRES_LOAD_MODE=relational_only \
  EVYDENCE_SKIP_MIGRATIONS=true \
  EVYDENCE_OBJECT_STORE=filesystem \
  EVYDENCE_OBJECT_DIR="$workdir/objects" \
  EVYDENCE_WORKER_POLL_INTERVAL=100ms \
  "$workdir/evydence-worker" >"$workdir/worker.stdout" 2>"$workdir/worker.stderr" &
  worker_pid="$!"
  sleep 0.5
  if ! kill -0 "$worker_pid" >/dev/null 2>&1; then
    printf '%s\n' "black-box-demo-check: worker process exited during startup" >&2
    sed -n '1,120p' "$workdir/worker.stderr" >&2 || true
    return 1
  fi
}

start_api first true
if [ -n "${EVYDENCE_BLACK_BOX_EXPECTED_VERSION:-}" ]; then
  curl -fsS "$api_url/v1/version" >"$workdir/version.json"
  jq -e --arg version "$EVYDENCE_BLACK_BOX_EXPECTED_VERSION" --arg commit "${EVYDENCE_BLACK_BOX_EXPECTED_COMMIT:-}" --arg manifest "${EVYDENCE_BLACK_BOX_EXPECTED_RELEASE_MANIFEST_DIGEST:-}" \
    '.data.version == $version and .data.commit == $commit and .data.release_manifest_digest == $manifest and .data.version != "dev"' \
    "$workdir/version.json" >/dev/null
fi
if ! api_key="$(jq -er '.secret' "$workdir/api-first.stdout")"; then
  : >"$workdir/api-first.stdout"
  printf '%s\n' "black-box-demo-check: bootstrap secret output was not parseable" >&2
  exit 1
fi
: >"$workdir/api-first.stdout"
start_worker

EVYDENCE_URL="$api_url" \
EVYDENCE_API_KEY="$api_key" \
EVYDENCE_DEMO_OUTDIR="$workdir/demo" \
examples/end-to-end-release-evidence/run-local-demo.sh >"$workdir/demo.stdout"

release_id="$(jq -er '.data.id' "$workdir/demo/release.json")"
jq -e --arg release_id "$release_id" '.data.release_id == $release_id' "$workdir/demo/release-readiness.json" >/dev/null
jq -e '.data.result == "passed"' "$workdir/demo/audit-chain-verification.json" >/dev/null

kill "$api_pid" >/dev/null 2>&1 || true
wait "$api_pid" >/dev/null 2>&1 || true
api_pid=""

start_api restart false
curl -fsS "$api_url/v1/reports/release-readiness?release_id=$release_id" \
  -H "Authorization: Bearer $api_key" \
  >"$workdir/restarted-readiness.json"
jq -e --arg release_id "$release_id" '.data.release_id == $release_id' "$workdir/restarted-readiness.json" >/dev/null

pending_jobs="$(psql "$EVYDENCE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -qAt -c "SELECT count(*) FROM $schema.outbox_jobs WHERE status IN ('queued', 'retrying', 'running')")"
if [ "$pending_jobs" != "0" ]; then
  printf '%s\n' "black-box-demo-check: pending outbox jobs remain after demo: $pending_jobs" >&2
  exit 1
fi

printf '%s\n' "black-box-demo-check: API, worker, PostgreSQL persistence, restart, readiness, package, and audit-chain flow passed"
