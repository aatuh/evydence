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
make migration-compatibility-check

workdir="tmp/production-check"
rm -rf "$workdir"
mkdir -p "$workdir"

go build -o "$workdir/evydence" ./cmd/evydence
cp openapi.yaml "$workdir/openapi.yaml"

"$workdir/evydence" release manifest \
  --out "$workdir/evydence-release-manifest.json" \
  "$workdir/evydence" \
  "$workdir/openapi.yaml"

"$workdir/evydence" release keygen \
  --private-out "$workdir/release-private.key" \
  --public-out "$workdir/release-public.key" >/dev/null

"$workdir/evydence" release sign \
  --manifest "$workdir/evydence-release-manifest.json" \
  --private-key "$workdir/release-private.key" \
  --out "$workdir/evydence-release-manifest.sig.json"

"$workdir/evydence" release verify \
  --manifest "$workdir/evydence-release-manifest.json" \
  --signature "$workdir/evydence-release-manifest.sig.json"

printf '%s\n' "production-check: release signing smoke test passed"
printf '%s\n' "Evydence production readiness checks passed"
