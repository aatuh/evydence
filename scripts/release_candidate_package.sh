#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

if [[ "${1:-}" == "--plan" && "$#" == 1 ]]; then
  exec python3 scripts/support_matrix.py --release-plan
fi
if [[ "$#" != 1 ]]; then
  echo "usage: scripts/release_candidate_package.sh <vX.Y.Z-rc.N> | --plan" >&2
  exit 2
fi
tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "usage: scripts/release_candidate_package.sh <vX.Y.Z-rc.N>" >&2
  exit 2
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
  echo "release candidate tag must look like v0.1.0-rc.1" >&2
  exit 2
fi
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release candidate packaging must run inside a git checkout" >&2
  exit 2
fi
initial_status="$(git status --porcelain --untracked-files=all)"
if [[ -n "$initial_status" ]]; then
  echo "release candidate packaging requires a clean worktree" >&2
  exit 2
fi
if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  if [[ "${EVYDENCE_RELEASE_ALLOW_EXISTING_TAG:-}" != "1" ]]; then
    echo "release candidate tag already exists locally: ${tag}" >&2
    exit 2
  fi
fi
build_commit="$(git rev-parse --verify HEAD)"
expected_go="$(python3 scripts/support_matrix.py --go-current)"
build_go_version="$(go env GOVERSION)"
if [[ "$build_go_version" != "go${expected_go}" ]]; then
  echo "release candidate packaging requires the declared current Go compiler" >&2
  exit 2
fi
targets_text="$(python3 scripts/support_matrix.py --release-targets)"
mapfile -t targets <<<"$targets_text"
if [[ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]]; then
  echo "EVYDENCE_TEST_DATABASE_URL is required for release candidate packaging" >&2
  exit 2
fi

signing_key_b64="${EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64:-${RELEASE_SIGNING_PRIVATE_KEY_B64:-}}"
if [[ -z "$signing_key_b64" ]]; then
  echo "EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64 or RELEASE_SIGNING_PRIVATE_KEY_B64 is required" >&2
  exit 2
fi
RELEASE_CANDIDATE_SIGNING_KEY_B64="$signing_key_b64" python3 - <<'PY'
import base64
import os
import sys

raw = os.environ.get("RELEASE_CANDIDATE_SIGNING_KEY_B64", "").strip()
try:
    decoded = base64.b64decode(raw, validate=True)
except Exception:
    print("release signing key must be base64", file=sys.stderr)
    sys.exit(2)
if len(decoded) != 64:
    print("release signing key must decode to a 64-byte Ed25519 private key", file=sys.stderr)
    sys.exit(2)
PY

echo "Packaging Evydence release candidate ${tag}"
make production-check

validated_commit="$(git rev-parse --verify HEAD)"
validated_status="$(git status --porcelain --untracked-files=all)"
if [[ "$validated_commit" != "$build_commit" || -n "$validated_status" ]]; then
  echo "release candidate source changed during validation" >&2
  exit 2
fi

distdir="dist/${tag}"
workdir="tmp/release-candidate/${tag}"
rm -rf "$distdir" "$workdir"
install -m 755 -d "$distdir" "$workdir"
archives=()
archive_paths=()

build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
build_manifest="$workdir/release-build-manifest.json"
python3 - "$tag" "$build_commit" "$build_time" "$build_go_version" "$build_manifest" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

tag, commit, build_time, go_version, output = sys.argv[1:]
root = Path.cwd()

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()

migrations = [
    {"path": str(path), "digest": sha256(path)}
    for path in sorted((root / "migrations").rglob("*"))
    if path.is_file()
]
manifest = {
    "schema_version": "evydence-release-build-manifest.v1",
    "tag": tag,
    "commit": commit,
    "build_time": build_time,
    "go_version": go_version,
    "materials": [
        {"path": "openapi.yaml", "digest": sha256(root / "openapi.yaml")},
        {"path": "release/support-matrix.json", "digest": sha256(root / "release/support-matrix.json")},
        *migrations,
    ],
    "limitations": [
        "This pre-build manifest binds source and release inputs used to inject API runtime identity.",
        "The final signed evydence-release-manifest.json additionally covers packaged binaries and release artifacts.",
        "It is not a certification, legal compliance conclusion, or secure-release guarantee.",
    ],
}
Path(output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
build_release_manifest_digest="sha256:$(sha256sum "$build_manifest" | awk '{print $1}')"
api_ldflags="$(EVYDENCE_BUILD_VERSION="$tag" EVYDENCE_BUILD_COMMIT="$build_commit" EVYDENCE_BUILD_TIME="$build_time" EVYDENCE_BUILD_DIRTY=false EVYDENCE_BUILD_GO_VERSION="$build_go_version" EVYDENCE_BUILD_RELEASE_MANIFEST_DIGEST="$build_release_manifest_digest" sh scripts/build_ldflags.sh)"

for target in "${targets[@]}"; do
  commands_text="$(python3 scripts/support_matrix.py --commands "$target")"
  mapfile -t commands <<<"$commands_text"
  goos="${target%/*}"
  goarch="${target#*/}"
  outdir="${workdir}/evydence_${tag}_${goos}_${goarch}"
  mkdir -p "$outdir"
  for command in "${commands[@]}"; do
    suffix=""
    if [[ "$goos" == "windows" ]]; then
      suffix=".exe"
    fi
    if [[ "$command" == "evydence-api" ]]; then
      GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "-s -w $api_ldflags" \
        -o "${outdir}/${command}${suffix}" "./cmd/${command}"
    else
      GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "-s -w" \
        -o "${outdir}/${command}${suffix}" "./cmd/${command}"
    fi
  done
  cp LICENSE README.md CHANGELOG.md "$outdir/"
  if [[ "$goos" == "windows" ]]; then
    archive="evydence_${tag}_${goos}_${goarch}.zip"
    (cd "$workdir" && zip -qr "${repo_root}/${distdir}/${archive}" "evydence_${tag}_${goos}_${goarch}")
  else
    archive="evydence_${tag}_${goos}_${goarch}.tar.gz"
    tar -C "$workdir" -czf "${distdir}/${archive}" "evydence_${tag}_${goos}_${goarch}"
  fi
  archives+=("$archive")
  archive_paths+=("${distdir}/${archive}")
done

cp openapi.yaml "$distdir/openapi.yaml"
cp "$build_manifest" "$distdir/release-build-manifest.json"
cp coverage.out "$distdir/coverage.out"
cp tmp/release-check-summary.txt "$distdir/release-check-summary.txt"
notes_source="docs/reference/release-notes-${tag}.md"
if [[ ! -f "$notes_source" ]]; then
  notes_source="docs/reference/release-notes-template.md"
fi
cp "$notes_source" "$distdir/release-notes.md"
sed -i.bak "s/{{TAG}}/${tag}/g; s/v0.1.0-rc.1/${tag}/g" "$distdir/release-notes.md"
rm -f "$distdir/release-notes.md.bak"

(cd "$distdir" && sha256sum openapi.yaml > openapi.sha256)
(cd "$repo_root" && find migrations -type f -print | LC_ALL=C sort | xargs sha256sum > "$distdir/migrations.sha256")
python3 scripts/release_evidence_metadata.py "$tag" "$distdir"

(cd "$distdir" && sha256sum \
  "${archives[@]}" \
  openapi.yaml \
  openapi.sha256 \
  evydence-release-sbom.cdx.json \
  evydence-release-provenance.json \
  evydence-release-provenance.intoto.jsonl \
  release-build-manifest.json \
  coverage.out \
  release-check-summary.txt \
  migrations.sha256 \
  release-notes.md > SHA256SUMS)

signing_dir="${workdir}/signing"
install -m 700 -d "$signing_dir"
signing_key="${signing_dir}/private.key"
umask 077
printf '%s' "$signing_key_b64" > "$signing_key"

tar -xzf "${distdir}/evydence_${tag}_linux_amd64.tar.gz" -C "$signing_dir"
cli="${signing_dir}/evydence_${tag}_linux_amd64/evydence"
"$cli" release manifest \
  --out "$distdir/evydence-release-manifest.json" \
  "${archive_paths[@]}" \
  "$distdir/openapi.yaml" \
  "$distdir/openapi.sha256" \
  "$distdir/evydence-release-sbom.cdx.json" \
  "$distdir/evydence-release-provenance.json" \
  "$distdir/evydence-release-provenance.intoto.jsonl" \
  "$distdir/release-build-manifest.json" \
  "$distdir/coverage.out" \
  "$distdir/release-check-summary.txt" \
  "$distdir/migrations.sha256" \
  "$distdir/release-notes.md" \
  "$distdir/SHA256SUMS"
"$cli" release sign \
  --manifest "$distdir/evydence-release-manifest.json" \
  --private-key "$signing_key" \
  --out "$distdir/evydence-release-manifest.sig.json"
rm -f "$signing_key"
cp "$distdir/evydence-release-manifest.sig.json" "$distdir/evydence-release-manifest.sig"
"$cli" release verify \
  --manifest "$distdir/evydence-release-manifest.json" \
  --signature "$distdir/evydence-release-manifest.sig.json"

scripts/release_candidate_validate.sh "$tag"
echo "release candidate package written: ${distdir}"
