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
  if ! grep -F -- "$text" "$file" >/dev/null; then
    printf '%s\n' "release-acceptance: $file missing text: $text" >&2
    exit 2
  fi
}

reject_text() {
  text="$1"
  if grep -R -i -- "$text" README.md docs COMMERCIAL.md GOVERNANCE.md CONTRIBUTING.md SECURITY.md SUPPORT.md TRADEMARKS.md RELEASE_EVIDENCE.md CHANGELOG.md >/dev/null; then
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
  CODEOWNERS \
  .dockerignore \
  .github/ISSUE_TEMPLATE.md \
  .github/pull_request_template.md \
  .github/workflows/codeql.yml \
  .github/workflows/container-image.yml \
  README.md \
  docs/README.md \
  docs/reference/release-candidate.md \
  docs/reference/release-evidence-index.md \
  docs/reference/maintainer-review-policy.md \
  docs/reference/roadmap.md \
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
require_text .github/ISSUE_TEMPLATE.md "private vulnerability reporting"
require_text .github/ISSUE_TEMPLATE.md "raw evidence payloads"
require_text .github/pull_request_template.md "tenant isolation"
require_text .github/pull_request_template.md "Sensitive Data Check"
require_text CODEOWNERS "internal/app/"
require_text CODEOWNERS "docs/reference/release-evidence-index.md"
require_text .github/workflows/codeql.yml "github/codeql-action/analyze@7211b7c8077ea37d8641b6271f6a365a22a5fbfa"
require_text .github/workflows/codeql.yml "security-and-quality"
require_text .github/workflows/ci.yml "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
require_text .github/workflows/release-artifacts.yml "contents: read"
require_text .github/workflows/release-artifacts.yml "EVYDENCE_RELEASE_PUBLISH_TOKEN"
require_text .github/workflows/release-artifacts.yml "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
require_text .github/workflows/release-artifacts.yml "--repo \"\${repo}\""
if grep -F "contents: write" .github/workflows/release-artifacts.yml >/dev/null; then
  printf '%s\n' "release-acceptance: release artifact workflow must not grant GITHUB_TOKEN contents: write" >&2
  exit 2
fi
require_text .github/workflows/container-image.yml "ghcr.io/\${{ github.repository }}"
require_text .github/workflows/container-image.yml "EVYDENCE_GHCR_PUBLISH_TOKEN"
if grep -F "packages: write" .github/workflows/container-image.yml >/dev/null; then
  printf '%s\n' "release-acceptance: container image workflow must not grant GITHUB_TOKEN packages: write" >&2
  exit 2
fi
require_text .github/workflows/container-image.yml "cosign sign --yes"
require_text .github/workflows/container-image.yml "cosign verify"
require_text .github/workflows/container-image.yml "evydence-container-image-manifest.json"
require_text .github/workflows/scorecard.yml "ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a"
require_text .github/workflows/scorecard.yml "publish_results: true"
require_text .github/workflows/scorecard-sarif.yml "publish_results: false"
require_text .github/workflows/scorecard-sarif.yml "github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa"
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
require_text docs/reference/release-candidate.md "Release evidence index"
require_text docs/reference/release-evidence-index.md "evydence-release-manifest.sig.json"
require_text docs/reference/release-evidence-index.md "evydence-release-manifest.sig"
require_text docs/reference/release-evidence-index.md "evydence-release-provenance.intoto.jsonl"
require_text docs/reference/release-evidence-index.md "evydence-container-image-manifest.json"
require_text docs/reference/release-evidence-index.md "sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888"
require_text docs/reference/release-evidence-index.md "not legal compliance proof"
require_text docs/reference/maintainer-review-policy.md "CODEOWNERS"
require_text docs/reference/maintainer-review-policy.md "tenant-scoped resources cannot cross tenant boundaries"
require_text docs/reference/maintainer-review-policy.md "OpenSSF Scorecard and Scorecard SARIF remain"
require_text docs/reference/roadmap.md "one API writer replica"
require_text docs/reference/roadmap.md "Release candidates"

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
