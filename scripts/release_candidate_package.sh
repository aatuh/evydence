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
env -i PATH="$PATH" python3 scripts/release_lifecycle.py check-tag "$tag" >/dev/null
# Keep release-only settings out of compiler, validation and runtime children.
signing_key_b64="${EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64:-${RELEASE_SIGNING_PRIVATE_KEY_B64:-}}"
release_allow_existing_tag="${EVYDENCE_RELEASE_ALLOW_EXISTING_TAG:-}"
release_syft="${EVYDENCE_RELEASE_SYFT:-}"
export -n signing_key_b64 release_allow_existing_tag release_syft
unset EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64 RELEASE_SIGNING_PRIVATE_KEY_B64 EVYDENCE_RELEASE_ALLOW_EXISTING_TAG EVYDENCE_RELEASE_SYFT

for archive_tool in tar zip sha256sum; do
  if ! command -v "$archive_tool" >/dev/null 2>&1; then
    echo "release candidate packaging requires archive tool: $archive_tool" >&2
    exit 2
  fi
done

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
  if [[ "$release_allow_existing_tag" != "1" ]]; then
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

if [[ -z "$release_syft" ]]; then
  echo "EVYDENCE_RELEASE_SYFT is required; prepare it with make release-evidence-tools" >&2
  exit 2
fi
python3 scripts/release_evidence_tools.py --verify-executable "$release_syft"
python3 scripts/release_notes.py --tag "$tag" check

echo "Packaging Evydence release candidate ${tag}"
make production-check

validated_commit="$(git rev-parse --verify HEAD)"
validated_status="$(git status --porcelain --untracked-files=all)"
if [[ "$validated_commit" != "$build_commit" || -n "$validated_status" ]]; then
  echo "release candidate source changed during validation" >&2
  exit 2
fi

repro_comparison="$(mktemp "${TMPDIR:-/tmp}/evydence-release-comparison.XXXXXXXX")"
make --silent --no-print-directory reproducible-build-check TAG="$tag" > "$repro_comparison"

distdir="dist/${tag}"
workdir="tmp/release-candidate/${tag}"
rm -rf "$distdir" "$workdir"
install -m 755 -d "$distdir" "$workdir"
archives=()
archive_paths=()

python3 scripts/release_build.py --tag "$tag" --output "$distdir" \
  --work "$workdir" --expected-commit "$build_commit"
build_manifest="$workdir/release-build-manifest.json"
for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  suffix="tar.gz"
  if [[ "$goos" == "windows" ]]; then
    suffix="zip"
  fi
  archive="evydence_${tag}_${goos}_${goarch}.${suffix}"
  archives+=("$archive")
  archive_paths+=("${distdir}/${archive}")
done

packaged_commit="$(git rev-parse --verify HEAD)"
packaged_status="$(git status --porcelain --untracked-files=all)"
if [[ "$packaged_commit" != "$build_commit" || -n "$packaged_status" ]]; then
  echo "release candidate source changed during artifact build" >&2
  exit 2
fi

python3 scripts/reproducible_build.py verify-candidate \
  --archives "$distdir" --work "$workdir" --comparison "$repro_comparison" \
  --tag "$tag" --expected-commit "$build_commit"
printf 'release candidate bytes match comparison: %s\n' "$repro_comparison"

cp openapi.yaml "$distdir/openapi.yaml"
cp "$build_manifest" "$distdir/release-build-manifest.json"
cp coverage.out "$distdir/coverage.out"
cp tmp/release-check-summary.txt "$distdir/release-check-summary.txt"
python3 scripts/release_notes.py --tag "$tag" emit > "$distdir/release-notes.md"

(cd "$distdir" && sha256sum openapi.yaml > openapi.sha256)
(cd "$repo_root" && find migrations -type f -print | LC_ALL=C sort | xargs sha256sum > "$distdir/migrations.sha256")
python3 scripts/release_evidence_metadata.py "$tag" "$distdir" --syft "$release_syft"
python3 scripts/release_evidence_verify.py --dist "$distdir" --tag "$tag" --expected-commit "$build_commit"
evidence_names=(evydence-release-evidence-index.json)
evidence_paths=("$distdir/evydence-release-evidence-index.json")
for evidence_path in "$distdir"/evydence-sbom-*.cdx.json; do
  evidence_names+=("${evidence_path##*/}")
  evidence_paths+=("$evidence_path")
done

(cd "$distdir" && sha256sum \
  "${archives[@]}" \
  openapi.yaml \
  openapi.sha256 \
  evydence-release-sbom.cdx.json \
  evydence-release-provenance.json \
  evydence-release-provenance.intoto.jsonl \
  "${evidence_names[@]}" \
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
  "${evidence_paths[@]}" \
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
