#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "usage: scripts/release_candidate_validate.sh <vX.Y.Z-rc.N>" >&2
  exit 2
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
  echo "release candidate tag must look like v0.1.0-rc.1" >&2
  exit 2
fi

distdir="dist/${tag}"
if [[ ! -d "$distdir" ]]; then
  echo "release candidate dist directory missing: $distdir" >&2
  exit 2
fi

required=(
  "SHA256SUMS"
  "openapi.yaml"
  "openapi.sha256"
  "evydence-release-sbom.cdx.json"
  "evydence-release-provenance.json"
  "evydence-release-provenance.intoto.jsonl"
  "evydence-release-evidence-index.json"
  "migrations.sha256"
  "release-build-manifest.json"
  "coverage.out"
  "release-check-summary.txt"
  "release-notes.md"
  "evydence-release-manifest.json"
  "evydence-release-manifest.sig.json"
  "evydence-release-manifest.sig"
)
targets_text="$(python3 scripts/support_matrix.py --release-targets)"
mapfile -t targets <<<"$targets_text"
for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  suffix="tar.gz"
  if [[ "$goos" == "windows" ]]; then
    suffix="zip"
  fi
  required+=("evydence_${tag}_${goos}_${goarch}.${suffix}")
done
for file in "${required[@]}"; do
  if [[ ! -f "$distdir/$file" ]]; then
    echo "release candidate artifact missing: $distdir/$file" >&2
    exit 2
  fi
done

(cd "$distdir" && sha256sum -c SHA256SUMS >/dev/null)
(cd "$distdir" && sha256sum -c openapi.sha256 >/dev/null)
sha256sum -c "$distdir/migrations.sha256" >/dev/null

go run ./cmd/evydence release verify \
  --manifest "$distdir/evydence-release-manifest.json" \
  --signature "$distdir/evydence-release-manifest.sig.json" >/dev/null
cmp -s "$distdir/evydence-release-manifest.sig.json" "$distdir/evydence-release-manifest.sig"
python3 scripts/release_evidence_verify.py --dist "$distdir" --tag "$tag" \
  --expected-commit "$(git rev-parse --verify HEAD)"

grep -Fi "Controlled self-hosted production candidate" "$distdir/release-notes.md" >/dev/null
grep -Fi "not legal compliance proof" "$distdir/release-notes.md" >/dev/null
grep -Fi "not a certification" "$distdir/release-notes.md" >/dev/null
grep -Fi "not a secure-release guarantee" "$distdir/release-notes.md" >/dev/null
grep -Fi "complete SBOM proof" "$distdir/release-notes.md" >/dev/null
grep -Fi "authoritative vulnerability coverage" "$distdir/release-notes.md" >/dev/null
grep -Fi "single API writer replica" "$distdir/release-notes.md" >/dev/null
grep -Fi "full repository decomposition" "$distdir/release-notes.md" >/dev/null
grep -Fi "complete SBOM proof" "$distdir/evydence-release-sbom.cdx.json" >/dev/null
grep -Fi "not a SLSA level claim" "$distdir/evydence-release-provenance.json" >/dev/null
grep -Fi "not a SLSA level claim" "$distdir/evydence-release-provenance.intoto.jsonl" >/dev/null

if grep -R -i "automatically compliant\|certified secure\|legally sufficient\|SBOM is complete\|all vulnerabilities detected\|scanner findings are authoritative\|regulator-ready without review" "$distdir/release-notes.md" >/dev/null; then
  echo "release notes contain a prohibited product claim" >&2
  exit 2
fi
if find "$distdir" -type f \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) | grep . >/dev/null; then
  echo "release candidate artifact directory contains private key material" >&2
  exit 2
fi

echo "release candidate evidence validated: $tag"
