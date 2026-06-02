#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

fail() {
  printf '%s\n' "production-benchmark-check: $*" >&2
  exit 2
}

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  fail "EVYDENCE_TEST_DATABASE_URL is required"
fi

for tool in go jq psql python3 curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    fail "missing required tool: $tool"
  fi
done

workdir="${EVYDENCE_PRODUCTION_BENCHMARK_WORKDIR:-tmp/production-benchmark}"
case "$workdir" in
  tmp/*) ;;
  *) fail "EVYDENCE_PRODUCTION_BENCHMARK_WORKDIR must stay under tmp/" ;;
esac
case "$workdir" in
  *..*|*/.*|.*) fail "EVYDENCE_PRODUCTION_BENCHMARK_WORKDIR must not contain dot segments" ;;
esac

rm -rf "$workdir"
mkdir -p "$workdir"

now_ns() {
  python3 - <<'PY'
import time
print(time.monotonic_ns())
PY
}

started_ns="$(now_ns)"
EVYDENCE_BLACK_BOX_WORKDIR="$workdir/black-box" \
EVYDENCE_BLACK_BOX_KEEP_ARTIFACTS=1 \
scripts/black_box_demo_check.sh >"$workdir/black-box.stdout" 2>"$workdir/black-box.stderr"
ended_ns="$(now_ns)"

python3 - "$workdir" "$started_ns" "$ended_ns" <<'PY'
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

workdir = Path(sys.argv[1])
started_ns = int(sys.argv[2])
ended_ns = int(sys.argv[3])
duration_ms = round((ended_ns - started_ns) / 1_000_000, 3)
duration_seconds = max((ended_ns - started_ns) / 1_000_000_000, 0.001)

demo_dir = workdir / "black-box" / "demo"
object_root = workdir / "black-box" / "objects"

def count_files(root: Path):
    if not root.exists():
        return 0, 0
    files = [path for path in root.rglob("*") if path.is_file()]
    return len(files), sum(path.stat().st_size for path in files)

object_files, object_bytes = count_files(object_root)
demo_json_files = len(list(demo_dir.glob("*.json"))) if demo_dir.exists() else 0

release_id = ""
release_file = demo_dir / "release.json"
if release_file.exists():
    try:
        release_id = json.loads(release_file.read_text()).get("data", {}).get("id", "")
    except json.JSONDecodeError:
        release_id = ""

try:
    commit = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], text=True).strip()
except Exception:
    commit = "unknown"

scenario_operations = 12
summary = {
    "schema_version": "evydence-production-benchmark.v1.0.0",
    "benchmark": "golden_release_evidence_black_box",
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "commit": commit,
    "scenario": {
        "source": "examples/end-to-end-release-evidence/run-local-demo.sh",
        "api_writer_replicas": 1,
        "worker_replicas": 1,
        "database": "disposable PostgreSQL schema from EVYDENCE_TEST_DATABASE_URL",
        "object_store": "filesystem object store under controlled tmp workspace",
        "signing": "tenant signing path exercised by release bundle generation",
        "paths": [
            "HTTP API create/list/report calls",
            "PostgreSQL migrations and persistence",
            "filesystem object payload storage",
            "worker startup and outbox drain check",
            "release-readiness report",
            "customer package creation",
            "audit-chain verification",
            "API restart persistence check",
        ],
        "operation_count_estimate": scenario_operations,
    },
    "timings": {
        "black_box_total_ms": duration_ms,
        "estimated_operations_per_second": round(scenario_operations / duration_seconds, 3),
        "estimated_average_operation_ms": round(duration_ms / scenario_operations, 3),
    },
    "outputs": {
        "summary_path": str(workdir / "production-benchmark-summary.json"),
        "black_box_stdout": str(workdir / "black-box.stdout"),
        "black_box_stderr": str(workdir / "black-box.stderr"),
        "demo_json_files": demo_json_files,
        "object_files": object_files,
        "object_bytes": object_bytes,
        "release_id": release_id,
    },
    "limitations": [
        "This is a local regression benchmark, not a production capacity claim.",
        "Filesystem object storage is used so the run does not prove S3 or MinIO network latency.",
        "The run uses one API writer and one worker; it does not prove multi-writer API safety.",
        "The operation rate is estimated from the checked scenario wall clock and is not per-route latency.",
        "Provider-side KMS, HSM, identity provider, transparency log, and registry controls are not exercised.",
        "Database URL, API key secret, and bootstrap secret values are intentionally omitted from the summary.",
    ],
}

summary_path = workdir / "production-benchmark-summary.json"
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

text_path = workdir / "production-benchmark-summary.txt"
text_path.write_text(
    "\n".join(
        [
            "production-benchmark-check: passed",
            f"commit={commit}",
            f"black_box_total_ms={duration_ms}",
            f"estimated_operations_per_second={summary['timings']['estimated_operations_per_second']}",
            f"demo_json_files={demo_json_files}",
            f"object_files={object_files}",
            f"object_bytes={object_bytes}",
            "claim=local regression benchmark only",
            "",
        ]
    )
)
print(text_path.read_text(), end="")
PY

jq -e '.schema_version == "evydence-production-benchmark.v1.0.0" and .outputs.object_files > 0 and (.limitations | length >= 3)' \
  "$workdir/production-benchmark-summary.json" >/dev/null
