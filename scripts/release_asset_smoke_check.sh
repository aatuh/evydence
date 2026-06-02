#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

workdir="tmp/release-asset-smoke"
distdir="${workdir}/dist"
rm -rf "$workdir"
install -m 755 -d "$distdir"

fail() {
  printf '%s\n' "release-asset-smoke-check: $*" >&2
  exit 2
}

check_required() {
  local dir="$1"
  local required=(
    "SHA256SUMS"
    "openapi.yaml"
    "openapi.sha256"
    "migrations.sha256"
    "release-notes.md"
    "evydence-release-manifest.json"
    "evydence-release-manifest.sig.json"
    "evydence_v0.0.0-rc.0_linux_amd64.tar.gz"
  )
  local file
  for file in "${required[@]}"; do
    [[ -f "${dir}/${file}" ]] || return 1
  done
}

printf '%s\n' "synthetic release archive for local smoke verification" \
  > "${distdir}/evydence_v0.0.0-rc.0_linux_amd64.tar.gz"
cp openapi.yaml "${distdir}/openapi.yaml"
cat > "${distdir}/release-notes.md" <<'EOF'
# v0.0.0-rc.0

Controlled self-hosted production candidate smoke fixture.

This fixture is not legal compliance proof, not a certification, not complete
SBOM proof, not authoritative vulnerability coverage, and not a secure-release
guarantee.
EOF

(cd "$distdir" && sha256sum openapi.yaml > openapi.sha256)
find migrations -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "${distdir}/migrations.sha256"
(cd "$distdir" && sha256sum \
  evydence_v0.0.0-rc.0_linux_amd64.tar.gz \
  openapi.yaml \
  openapi.sha256 \
  migrations.sha256 \
  release-notes.md > SHA256SUMS)

(cd "$distdir" && sha256sum -c SHA256SUMS >/dev/null)
(cd "$distdir" && sha256sum -c openapi.sha256 >/dev/null)
sha256sum -c "${distdir}/migrations.sha256" >/dev/null

private_key="${workdir}/private.key"
public_key="${workdir}/public.key"
go run ./cmd/evydence release keygen \
  --private-out "$private_key" \
  --public-out "$public_key" >/dev/null
go run ./cmd/evydence release manifest \
  --out "${distdir}/evydence-release-manifest.json" \
  "${distdir}/evydence_v0.0.0-rc.0_linux_amd64.tar.gz" \
  "${distdir}/openapi.yaml" \
  "${distdir}/openapi.sha256" \
  "${distdir}/migrations.sha256" \
  "${distdir}/release-notes.md" \
  "${distdir}/SHA256SUMS" >/dev/null
go run ./cmd/evydence release sign \
  --manifest "${distdir}/evydence-release-manifest.json" \
  --private-key "$private_key" \
  --out "${distdir}/evydence-release-manifest.sig.json" >/dev/null
rm -f "$private_key"
check_required "$distdir" || fail "synthetic release asset set is incomplete"
go run ./cmd/evydence release verify \
  --manifest "${distdir}/evydence-release-manifest.json" \
  --signature "${distdir}/evydence-release-manifest.sig.json" >/dev/null

package_out="${workdir}/package-verify.txt"
go run ./cmd/evydence package verify \
  --archive examples/end-to-end-release-evidence/sample-customer-package.zip \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example > "$package_out"
grep -F "customer package verified" "$package_out" >/dev/null

bad_checksum="${workdir}/bad-checksum"
cp -R "$distdir" "$bad_checksum"
printf '%s\n' "tampered" >> "${bad_checksum}/openapi.yaml"
if (cd "$bad_checksum" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
  fail "tampered checksum unexpectedly verified"
fi

missing_asset="${workdir}/missing-asset"
cp -R "$distdir" "$missing_asset"
rm -f "${missing_asset}/openapi.sha256"
if check_required "$missing_asset"; then
  fail "missing asset set unexpectedly passed required-file check"
fi

bad_manifest="${workdir}/bad-manifest.json"
python3 - "${distdir}/evydence-release-manifest.json" "$bad_manifest" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
doc = json.loads(source.read_text(encoding="utf-8"))
doc["tampered"] = True
target.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
PY
if go run ./cmd/evydence release verify \
  --manifest "$bad_manifest" \
  --signature "${distdir}/evydence-release-manifest.sig.json" >/dev/null 2>&1; then
  fail "tampered release manifest unexpectedly verified"
fi

if go run ./cmd/evydence package verify \
  --archive examples/end-to-end-release-evidence/sample-customer-package.zip \
  --expected-package-id csp_wrong >/dev/null 2>&1; then
  fail "wrong expected package id unexpectedly verified"
fi

cat > "${workdir}/summary.txt" <<'EOF'
release_asset_smoke=passed
checksums=passed
signed_manifest=passed
package_verify=passed
failure_cases=passed
EOF
printf '%s\n' "release-asset-smoke-check: passed"
