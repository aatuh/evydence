#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' "production-check: EVYDENCE_TEST_DATABASE_URL is required" >&2
  exit 2
fi

printf '%s\n' "Running Evydence production readiness checks"

make release-check
make coverage-check

workdir="tmp/production-check"
rm -rf "$workdir"
mkdir -p "$workdir/dist"

go build -o "$workdir/dist/evydence" ./cmd/evydence
cp openapi.yaml "$workdir/dist/openapi.yaml"

"$workdir/dist/evydence" release manifest \
  --out "$workdir/evydence-release-manifest.json" \
  "$workdir/dist/evydence" \
  "$workdir/dist/openapi.yaml"

"$workdir/dist/evydence" release keygen \
  --private-out "$workdir/release-private.key" \
  --public-out "$workdir/release-public.key" >/dev/null

"$workdir/dist/evydence" release sign \
  --manifest "$workdir/evydence-release-manifest.json" \
  --private-key "$workdir/release-private.key" \
  --out "$workdir/evydence-release-manifest.sig.json"

"$workdir/dist/evydence" release verify \
  --manifest "$workdir/evydence-release-manifest.json" \
  --signature "$workdir/evydence-release-manifest.sig.json"

printf '%s\n' "production-check: release signing smoke test passed"
printf '%s\n' "Evydence production readiness checks passed"
