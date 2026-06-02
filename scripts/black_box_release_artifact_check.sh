#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

fail() {
  printf '%s\n' "black-box-release-artifact-check: $*" >&2
  exit 2
}

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  fail "EVYDENCE_TEST_DATABASE_URL is required"
fi

for tool in curl go jq psql python3 sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    fail "missing required tool: $tool"
  fi
done

workdir="${EVYDENCE_BLACK_BOX_RELEASE_WORKDIR:-tmp/black-box-release-artifact}"
case "$workdir" in
  tmp/*) ;;
  *) fail "EVYDENCE_BLACK_BOX_RELEASE_WORKDIR must stay under tmp/" ;;
esac
case "$workdir" in
  *..*|*/.*|.*) fail "EVYDENCE_BLACK_BOX_RELEASE_WORKDIR must not contain dot segments" ;;
esac

rm -rf "$workdir"
release_dir="$workdir/release/evydence_linux_amd64"
run_dir="$workdir/run"
mkdir -p "$release_dir" "$run_dir"

go build -trimpath -o "$release_dir/evydence" ./cmd/evydence
go build -trimpath -o "$release_dir/evydence-api" ./cmd/evydence-api
go build -trimpath -o "$release_dir/evydence-worker" ./cmd/evydence-worker
go build -trimpath -o "$release_dir/evydence-migrate" ./cmd/evydence-migrate
(cd "$release_dir" && sha256sum evydence evydence-api evydence-worker evydence-migrate > SHA256SUMS)

EVYDENCE_BLACK_BOX_WORKDIR="$run_dir" \
EVYDENCE_BLACK_BOX_KEEP_ARTIFACTS=1 \
EVYDENCE_BLACK_BOX_API_BIN="$release_dir/evydence-api" \
EVYDENCE_BLACK_BOX_WORKER_BIN="$release_dir/evydence-worker" \
scripts/black_box_demo_check.sh >"$workdir/black-box.stdout" 2>"$workdir/black-box.stderr"

python3 - "$workdir" "$release_dir" "$run_dir" <<'PY'
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

workdir = Path(sys.argv[1])
release_dir = Path(sys.argv[2])
run_dir = Path(sys.argv[3])
demo_dir = run_dir / "demo"
object_root = run_dir / "objects"

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def count_files(root: Path):
    if not root.exists():
        return 0, 0
    files = [path for path in root.rglob("*") if path.is_file()]
    return len(files), sum(path.stat().st_size for path in files)

try:
    commit = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], text=True).strip()
except Exception:
    commit = "unknown"

binaries = []
for name in ["evydence", "evydence-api", "evydence-worker", "evydence-migrate"]:
    path = release_dir / name
    binaries.append(
        {
            "name": name,
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": sha256(path),
        }
    )

object_files, object_bytes = count_files(object_root)
demo_json_files = len(list(demo_dir.glob("*.json"))) if demo_dir.exists() else 0

summary = {
    "schema_version": "evydence-black-box-release-artifact.v1.0.0",
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "commit": commit,
    "artifact_shape": "release-style linux_amd64 binary directory",
    "binaries": binaries,
    "scenario": {
        "source": "scripts/black_box_demo_check.sh",
        "database": "disposable PostgreSQL schema from EVYDENCE_TEST_DATABASE_URL",
        "object_store": "filesystem object store under controlled tmp workspace",
        "api_restart": True,
        "worker_started": True,
        "release_readiness_verified": True,
        "customer_package_created": True,
        "audit_chain_verified": True,
    },
    "outputs": {
        "summary_path": str(workdir / "black-box-release-artifact-summary.json"),
        "checksums_path": str(release_dir / "SHA256SUMS"),
        "black_box_stdout": str(workdir / "black-box.stdout"),
        "black_box_stderr": str(workdir / "black-box.stderr"),
        "demo_json_files": demo_json_files,
        "object_files": object_files,
        "object_bytes": object_bytes,
    },
    "limitations": [
        "This check runs release-style local binaries, not a published GitHub Release asset.",
        "The object store is local filesystem storage, not live S3 or MinIO network storage.",
        "The check avoids live external providers and does not prove KMS, HSM, SSO, registry, or transparency-provider behavior.",
        "The summary intentionally excludes API keys, database URLs, bootstrap secrets, bearer tokens, and raw evidence payloads.",
    ],
}

summary_path = workdir / "black-box-release-artifact-summary.json"
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

text_path = workdir / "black-box-release-artifact-summary.txt"
text_path.write_text(
    "\n".join(
        [
            "black-box-release-artifact-check: passed",
            f"commit={commit}",
            f"binaries={len(binaries)}",
            f"demo_json_files={demo_json_files}",
            f"object_files={object_files}",
            f"object_bytes={object_bytes}",
            "claim=release-style binary smoke test only",
            "",
        ]
    )
)
print(text_path.read_text(), end="")
PY

jq -e '.schema_version == "evydence-black-box-release-artifact.v1.0.0" and (.binaries | length == 4) and .outputs.object_files > 0 and (.limitations | length >= 3)' \
  "$workdir/black-box-release-artifact-summary.json" >/dev/null

if find "$workdir" -type f \( -name '*.json' -o -name '*.txt' -o -name '*.stdout' -o -name '*.stderr' \) -exec grep -I -l 'evy_' {} + | grep -q .; then
  printf '%s\n' "black-box-release-artifact-check: generated artifacts leaked an API key-like secret" >&2
  exit 1
fi
