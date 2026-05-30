#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

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
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "release candidate packaging requires a clean worktree" >&2
  exit 2
fi
if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  if [[ "${EVYDENCE_RELEASE_ALLOW_EXISTING_TAG:-}" != "1" ]]; then
    echo "release candidate tag already exists locally: ${tag}" >&2
    exit 2
  fi
fi
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

distdir="dist/${tag}"
workdir="tmp/release-candidate/${tag}"
rm -rf "$distdir" "$workdir"
install -m 755 -d "$distdir" "$workdir"

commands=(evydence evydence-api evydence-worker evydence-migrate)
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  outdir="${workdir}/evydence_${tag}_${goos}_${goarch}"
  mkdir -p "$outdir"
  for command in "${commands[@]}"; do
    suffix=""
    if [[ "$goos" == "windows" ]]; then
      suffix=".exe"
    fi
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
      go build -trimpath -ldflags "-s -w" \
      -o "${outdir}/${command}${suffix}" "./cmd/${command}"
  done
  cp LICENSE README.md CHANGELOG.md "$outdir/"
  if [[ "$goos" == "windows" ]]; then
    (cd "$workdir" && zip -qr "${repo_root}/${distdir}/evydence_${tag}_${goos}_${goarch}.zip" "evydence_${tag}_${goos}_${goarch}")
  else
    tar -C "$workdir" -czf "${distdir}/evydence_${tag}_${goos}_${goarch}.tar.gz" "evydence_${tag}_${goos}_${goarch}"
  fi
done

cp openapi.yaml "$distdir/openapi.yaml"
cp coverage.out "$distdir/coverage.out"
cp tmp/release-check-summary.txt "$distdir/release-check-summary.txt"
cp docs/reference/release-notes-v0.1.0-rc.1.md "$distdir/release-notes.md"
sed -i.bak "s/v0.1.0-rc.1/${tag}/g" "$distdir/release-notes.md"
rm -f "$distdir/release-notes.md.bak"

(cd "$distdir" && sha256sum openapi.yaml > openapi.sha256)
(cd "$repo_root" && find migrations -type f -print | LC_ALL=C sort | xargs sha256sum > "$distdir/migrations.sha256")

(cd "$distdir" && sha256sum \
  evydence_${tag}_*.tar.gz \
  evydence_${tag}_*.zip \
  openapi.yaml \
  openapi.sha256 \
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
  "$distdir"/evydence_${tag}_*.tar.gz \
  "$distdir"/evydence_${tag}_*.zip \
  "$distdir/openapi.yaml" \
  "$distdir/openapi.sha256" \
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
"$cli" release verify \
  --manifest "$distdir/evydence-release-manifest.json" \
  --signature "$distdir/evydence-release-manifest.sig.json"

scripts/release_candidate_validate.sh "$tag"
echo "release candidate package written: ${distdir}"
