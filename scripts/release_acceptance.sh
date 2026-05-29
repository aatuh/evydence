#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

require_file() {
  if [ ! -f "$1" ]; then
    printf '%s\n' "release-acceptance: missing required file: $1" >&2
    exit 2
  fi
}

require_text() {
  file="$1"
  text="$2"
  if ! grep -F "$text" "$file" >/dev/null; then
    printf '%s\n' "release-acceptance: $file missing text: $text" >&2
    exit 2
  fi
}

reject_text() {
  text="$1"
  if grep -R -i "$text" README.md docs COMMERCIAL.md GOVERNANCE.md CONTRIBUTING.md SECURITY.md SUPPORT.md TRADEMARKS.md RELEASE_EVIDENCE.md CHANGELOG.md >/dev/null; then
    printf '%s\n' "release-acceptance: forbidden claim found: $text" >&2
    exit 2
  fi
}

printf '%s\n' "Running Evydence release acceptance checks"

make fast-check

for file in \
  LICENSE \
  COMMERCIAL.md \
  GOVERNANCE.md \
  CONTRIBUTING.md \
  SECURITY.md \
  SUPPORT.md \
  TRADEMARKS.md \
  RELEASE_EVIDENCE.md \
  CHANGELOG.md \
  .dockerignore \
  README.md \
  docs/README.md \
  docs/reference/release-candidate.md \
  docs/reference/release-validation.md; do
  require_file "$file"
done

require_text LICENSE "GNU AFFERO GENERAL PUBLIC LICENSE"
require_text COMMERCIAL.md "AGPL-3.0-only"
require_text COMMERCIAL.md "Commercial license exceptions"
require_text COMMERCIAL.md "compliance readiness"
require_text GOVERNANCE.md "tenant-scoped"
require_text GOVERNANCE.md "compliance and legal language stays conservative"
require_text CONTRIBUTING.md "contributor license agreement"
require_text CONTRIBUTING.md "EVYDENCE_TEST_DATABASE_URL"
require_text SECURITY.md "raw evidence payloads"
require_text SECURITY.md "tenant isolation"
require_text SECURITY.md "private security intake"
require_text SECURITY.md "Supported Versions And Scope"
require_text SUPPORT.md "sanitized logs"
require_text SUPPORT.md "release evidence artifacts"
require_text TRADEMARKS.md "Evydence fork"
require_text RELEASE_EVIDENCE.md "Release evidence is not a certification"
require_text RELEASE_EVIDENCE.md "make release-check"
require_text RELEASE_EVIDENCE.md "release-candidate"
require_text CHANGELOG.md "Unreleased"
require_text docs/reference/release-candidate.md "Controlled self-hosted production candidate"
require_text docs/reference/release-candidate.md "Use one API writer replica"
require_text docs/reference/release-candidate.md "OpenAPI checksum"
require_text docs/reference/release-candidate.md "migration checksum"

for pattern in \
  ".refs" \
  ".env.*" \
  ".api.env.*" \
  ".test.env.*" \
  "*.pem" \
  "*.key" \
  "release-evidence" \
  "backups" \
  "coverage.out" \
  "bin/" \
  "dist/" \
  "tmp/" \
  ".terraform" \
  "*.tfstate"; do
  require_text .dockerignore "$pattern"
done

require_text README.md "License, Security, Support, And Governance"
require_text README.md "AGPL-3.0-only"
require_text docs/README.md "Security policy"
require_text docs/README.md "Release evidence"

reject_text "automatically compliant"
reject_text "certified secure"
reject_text "legally sufficient"
reject_text "SBOM is complete"
reject_text "all vulnerabilities detected"
reject_text "scanner findings are authoritative"
reject_text "regulator-ready without review"

printf '%s\n' "Evydence release acceptance checks passed"
