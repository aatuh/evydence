#!/usr/bin/env bash
set -euo pipefail

repo="${EVYDENCE_RELEASE_REPO:-aatuh/evydence}"
tag="${1:-${TAG:-v0.1.0-rc.5}}"

if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "EVYDENCE_RELEASE_REPO must look like owner/name" >&2
  exit 2
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
  echo "release candidate tag must look like v0.1.0-rc.5" >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to download public release assets" >&2
  exit 2
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/evydence-release-verify.XXXXXX")"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

echo "Downloading ${repo} ${tag} into ${workdir}"
gh release download "$tag" --repo "$repo" --dir "$workdir"

(cd "$workdir" && sha256sum -c SHA256SUMS)
(cd "$workdir" && sha256sum -c openapi.sha256)
sha256sum -c "$workdir/migrations.sha256"

archive="$workdir/evydence_${tag}_linux_amd64.tar.gz"
if [[ ! -f "$archive" ]]; then
  echo "linux amd64 release archive missing: ${archive}" >&2
  exit 2
fi
tar -C "$workdir" -xzf "$archive"
cli="$workdir/evydence_${tag}_linux_amd64/evydence"
"$cli" release verify \
  --manifest "$workdir/evydence-release-manifest.json" \
  --signature "$workdir/evydence-release-manifest.sig.json"

if [[ -f "$workdir/evydence-release-manifest.sig" ]]; then
  cmp -s "$workdir/evydence-release-manifest.sig.json" "$workdir/evydence-release-manifest.sig"
fi
python3 - "$workdir/evydence-release-provenance.intoto.jsonl" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
line = path.read_text(encoding="utf-8").strip()
statement = json.loads(line)
if statement.get("_type") != "https://in-toto.io/Statement/v0.1":
    raise SystemExit("release provenance is not an in-toto statement")
if "not a SLSA level claim" not in json.dumps(statement, sort_keys=True):
    raise SystemExit("release provenance limitations are missing")
PY

echo "public release verified: ${repo} ${tag}"
