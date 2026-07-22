GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

TOOLS := golangci-lint gosec govulncheck
GOLANGCI_LINT_VERSION ?= v2.11.4
GOSEC_VERSION ?= v2.25.0
GOVULNCHECK_VERSION ?= v1.2.0

TAG ?=

.PHONY: help tools fmt lint vuln gosec test test-race fuzz-smoke coverage coverage-check openapi-check openapi-precision-check rendered-openapi-check meta-check release-truth-check persistence-decomposition-check backlog-check docs-check deploy-check sdk-check demo-check customer-cve-review-demo-check local-ci-simulation-check reviewer-package-workflow-check black-box-demo-check black-box-release-artifact-check benchmark-check package-viewer-check release-asset-smoke-check marketing-site-check marketing-site-production-check restore-rehearsal-check fast-check finalize release-acceptance release-check production-check release-candidate-check public-release-verify migration-compatibility-check release-check-local-postgres compose-up compose-down migrate live-postgres-check postgres-integration-test clean

help: ## Show help
	@awk 'BEGIN {FS=":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-18s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

tools: ## Install local QA tools
	@$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

fmt: ## Format Go files
	@$(GO) fmt ./...

lint: ## Run golangci-lint when installed
	@golangci-lint run ./...

vuln: ## Run govulncheck when installed
	@govulncheck ./...

gosec: ## Run gosec when installed
	@gosec -exclude-dir=.refs ./...

test: ## Run unit tests
	@$(GO) test ./...

fuzz-smoke: ## Run Go fuzz target seed corpora without a fuzzing campaign
	@$(GO) test ./internal/app -run '^Fuzz'

test-race: ## Run race tests
	@$(GO) test ./... -race -count=1

coverage: ## Run tests with coverage
	@$(GO) test ./... -coverprofile=coverage.out
	@$(GO) tool cover -func=coverage.out

coverage-check: ## Enforce the production coverage threshold; requires EVYDENCE_TEST_DATABASE_URL
	@scripts/coverage_check.sh

openapi.yaml: ## Generate committed OpenAPI source
	@$(GO) run ./cmd/openapi > openapi.yaml

openapi-check: openapi.yaml ## Validate OpenAPI generation and route contract tests
	@$(GO) test ./internal/adapters/httpapi -run 'TestRoutesValidateAndOpenAPIRenders'
	@$(GO) run ./cmd/openapi > /tmp/evydence-openapi.yaml
	@cmp -s openapi.yaml /tmp/evydence-openapi.yaml
	@scripts/render_openapi_docs.py --check

openapi-precision-check: ## Enforce current OpenAPI precision floor and broad-route ceiling
	@python3 scripts/openapi_precision_check.py

rendered-openapi-check: ## Validate generated static OpenAPI docs
	@scripts/render_openapi_docs.py --check

meta-check: ## Validate root legal, governance, support, and release-evidence metadata
	@test -f LICENSE
	@test -f COMMERCIAL.md
	@test -f GOVERNANCE.md
	@test -f CONTRIBUTING.md
	@test -f SECURITY.md
	@test -f SUPPORT.md
	@test -f TRADEMARKS.md
	@test -f CODE_OF_CONDUCT.md
	@test -f CODEOWNERS
	@test -f RELEASE_EVIDENCE.md
	@test -f CHANGELOG.md
	@test -f .dockerignore
	@test -f .github/dependabot.yml
	@test -f .github/workflows/scorecard.yml
	@test -f .github/workflows/container-image.yml
	@test -f .github/workflows/codeql.yml
	@test -f .github/workflows/marketing-site-pages.yml
	@test -f .github/ISSUE_TEMPLATE.md
	@test -f .github/ISSUE_TEMPLATE/bug_report.yml
	@test -f .github/ISSUE_TEMPLATE/feature_request.yml
	@test -f .github/ISSUE_TEMPLATE/docs.yml
	@test -f .github/ISSUE_TEMPLATE/production_support.yml
	@test -f .github/pull_request_template.md
	@test -x scripts/release_acceptance.sh
	@test -x scripts/release_candidate_package.sh
	@test -x scripts/release_candidate_validate.sh
	@test -x scripts/release_asset_smoke_check.sh
	@test -x scripts/release_evidence_metadata.py
	@grep -F 'GNU AFFERO GENERAL PUBLIC LICENSE' LICENSE >/dev/null
	@grep -F 'AGPL-3.0-only' COMMERCIAL.md >/dev/null
	@grep -F 'Commercial license exceptions' COMMERCIAL.md >/dev/null
	@grep -F 'License Decision Table' COMMERCIAL.md >/dev/null
	@grep -F 'This table is a practical routing aid, not legal advice.' COMMERCIAL.md >/dev/null
	@grep -F 'Discuss a commercial license exception' COMMERCIAL.md >/dev/null
	@grep -F 'Release Evidence Readiness Review' COMMERCIAL.md >/dev/null
	@grep -F 'one customer-safe package or evidence bundle' COMMERCIAL.md docs/commercial/product-landing-copy.md >/dev/null
	@grep -F 'Out of scope unless separately agreed' COMMERCIAL.md >/dev/null
	@grep -F 'contributor license agreement' CONTRIBUTING.md >/dev/null
	@grep -F 'First Contribution Path' CONTRIBUTING.md >/dev/null
	@grep -F 'Issue reports do not need a contributor license agreement' CONTRIBUTING.md >/dev/null
	@grep -F 'object-store paths' CONTRIBUTING.md >/dev/null
	@grep -F 'raw evidence payloads' SECURITY.md >/dev/null
	@grep -F 'release evidence artifacts' SUPPORT.md >/dev/null
	@grep -F 'Security vulnerability' .github/ISSUE_TEMPLATE/config.yml >/dev/null
	@grep -F 'private vulnerability reporting' .github/ISSUE_TEMPLATE.md >/dev/null
	@grep -F 'tenant isolation' .github/pull_request_template.md >/dev/null
	@grep -F 'internal/app/' CODEOWNERS >/dev/null
	@grep -F 'docs/reference/release-evidence-index.md' CODEOWNERS >/dev/null
	@grep -F 'OpenSSF Scorecard' .github/workflows/scorecard.yml >/dev/null
	@grep -F 'ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a' .github/workflows/scorecard.yml >/dev/null
	@grep -F 'OpenSSF Scorecard SARIF' .github/workflows/scorecard-sarif.yml >/dev/null
	@grep -F 'ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a' .github/workflows/scorecard-sarif.yml >/dev/null
	@grep -F 'github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa' .github/workflows/scorecard-sarif.yml >/dev/null
	@grep -F 'github/codeql-action/analyze@7211b7c8077ea37d8641b6271f6a365a22a5fbfa' .github/workflows/codeql.yml >/dev/null
	@grep -F 'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd' .github/workflows/ci.yml >/dev/null
	@grep -F 'actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c' .github/workflows/ci.yml >/dev/null
	@grep -F 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' .github/workflows/ci.yml >/dev/null
	@grep -F 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229' .github/workflows/ci.yml >/dev/null
	@grep -F 'ghcr.io/$${{ github.repository }}' .github/workflows/container-image.yml >/dev/null
	@grep -F 'cosign sign --yes' .github/workflows/container-image.yml >/dev/null
	@grep -F 'cosign verify' .github/workflows/container-image.yml >/dev/null
	@grep -F -- '--provenance=true' .github/workflows/container-image.yml >/dev/null
	@grep -F -- '--sbom=true' .github/workflows/container-image.yml >/dev/null
	@grep -F 'https://evydence.app' .github/workflows/marketing-site-pages.yml >/dev/null
	@grep -F 'G-XC2ESEHQ3W' Makefile >/dev/null
	@grep -F 'actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e' .github/workflows/marketing-site-pages.yml >/dev/null
	@grep -F 'actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa' .github/workflows/marketing-site-pages.yml >/dev/null
	@grep -F 'actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b' .github/workflows/marketing-site-pages.yml >/dev/null
	@grep -F 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020' .github/workflows/marketing-site-pages.yml >/dev/null
	@grep -F 'pages: write' .github/workflows/marketing-site-pages.yml >/dev/null
	@test -f site/marketing/public/CNAME
	@grep -Fx 'evydence.app' site/marketing/public/CNAME >/dev/null
	@grep -F 'Evydence fork' TRADEMARKS.md >/dev/null
	@grep -F 'Release evidence is not a certification' RELEASE_EVIDENCE.md >/dev/null
	@grep -F '.refs' .dockerignore >/dev/null
	@grep -F 'release-evidence' .dockerignore >/dev/null
	@grep -F 'backups' .dockerignore >/dev/null
	@grep -F '*.pem' .dockerignore >/dev/null

release-truth-check: ## Validate current release metadata against public docs and helper defaults
	@scripts/check_release_truth.py

persistence-decomposition-check: ## Validate generated persistence decomposition inventory
	@scripts/persistence_decomposition_inventory.py --check

backlog-check: ## Validate tracked execution backlog metadata
	@test -f .EVYDENCE_CODEX_BACKLOG.md
	@test -f docs/reference/world-class-backlog.md
	@test -f docs/reference/issue-labels.md
	@test -f .github/ISSUE_TEMPLATE/backlog-ticket.md
	@test -z "$$(rg -o '^### \[[ x]\] EVY-[0-9]+:' .EVYDENCE_CODEX_BACKLOG.md | sed -E 's/^### \[[ x]\] ([^:]+):/\1/' | sort | uniq -d)"
	@rg -F 'implementation tracking, not a production claim' docs/reference/world-class-backlog.md >/dev/null
	@rg -F 'Ticket ID' .github/ISSUE_TEMPLATE/backlog-ticket.md >/dev/null
	@rg -F 'Completion evidence' .github/ISSUE_TEMPLATE/backlog-ticket.md >/dev/null

docs-check: meta-check release-truth-check persistence-decomposition-check backlog-check rendered-openapi-check ## Validate canonical docs exist and avoid forbidden product claims
	@test -f README.md
	@test -f .production.env.example
	@test -f docs/README.md
	@test -f docs/buyer-overview.md
	@test -f docs/operator-overview.md
	@test -f docs/architecture.md
	@test -f docs/api.md
	@test -f docs/operations.md
	@test -f docs/kubernetes.md
	@test -f docs/air-gapped.md
	@test -f docs/release-signing.md
	@test -f docs/production-hardening.md
	@test -f docs/tutorials/evaluate-in-10-minutes.md
	@test -f docs/tutorials/customer-cve-review-demo.md
	@test -f docs/tutorials/getting-started.md
	@test -f docs/how-to/integrate-ci.md
	@test -f docs/how-to/install-and-operate.md
	@test -f docs/how-to/view-packages.md
	@test -f docs/how-to/publish-marketing-site.md
	@test -f docs/integrations/tool-templates.md
	@test -f docs/reference/configuration.md
	@test -f docs/reference/capability-map.md
	@test -f docs/reference/api-contract-matrix.md
	@test -f docs/reference/openapi.md
	@test -f docs/openapi/index.html
	@test -f site/marketing/public/api/index.html
	@test -f docs/reference/vulnerability-decisions.md
	@test -f docs/reference/observability.md
	@test -f docs/reference/capacity-and-failures.md
	@test -f docs/reference/benchmark-results.md
	@test -f docs/reference/production-readiness.md
	@test -f docs/reference/production-readiness-traceability.md
	@test -f docs/reference/production-internal-exit-checklist.md
	@test -f docs/reference/production-readiness-audit-closeout.md
	@test -f docs/reference/production-internal-score.md
	@test -f docs/reference/persistence-decomposition.md
	@test -f docs/reference/production-exit-review.md
	@test -f docs/reference/stable-v0.1.0-exit-criteria.md
	@test -f docs/reference/hardened-reference-deployment.md
	@test -f docs/reference/ha-strategy.md
	@test -f docs/reference/external-controls-matrix.md
	@test -f docs/reference/production-gate-troubleshooting.md
	@test -f docs/reference/upgrade-compatibility-policy.md
	@test -f docs/reference/release-candidate.md
	@test -f docs/reference/release-evidence-index.md
	@test -f docs/reference/release-notes-template.md
	@test -f docs/reference/release-notes-v0.1.0-rc.1.md
	@test -f docs/reference/maintainer-review-policy.md
	@test -f docs/reference/roadmap.md
	@test -f docs/reference/worker-outbox.md
	@test -f docs/reference/release-validation.md
	@test -f docs/reference/world-class-backlog.md
	@test -f docs/reference/issue-labels.md
	@test -f docs/reference/upload-manifest.md
	@test -f docs/how-to/review-customer-package.md
	@test -f docs/runbooks/key-rotation.md
	@test -f docs/runbooks/object-store-recovery.md
	@test -f schemas/upload-manifest.v1.schema.json
	@test -f docs/explanation/trust-model.md
	@test -f docs/collectors/source-snapshots.md
	@test -f docs/collectors/supply-chain.md
	@test -f docs/github-actions/end-to-end-release-evidence.md
	@test -f docs/github-actions/quickstart-release-evidence.yml
	@test -f docs/github-actions/release-evidence-workflow.yml
	@test -f docs/github-actions/upload-build/action.yml
	@test -f docs/gitlab/evydence-release-evidence.gitlab-ci.yml
	@test -f .github/workflows/release-artifacts.yml
	@test -f .github/workflows/container-image.yml
	@test -f .github/workflows/codeql.yml
	@test -f docs/sdk/README.md
	@test -f docs/sdk/quickstarts.md
	@for path in \
		"tutorials/evaluate-in-10-minutes.md" \
		"tutorials/customer-cve-review-demo.md" \
		"tutorials/getting-started.md" \
		"buyer-overview.md" \
		"operator-overview.md" \
		"how-to/install-and-operate.md" \
		"how-to/view-packages.md" \
		"how-to/review-customer-package.md" \
		"how-to/integrate-ci.md" \
		"integrations/tool-templates.md" \
		"api.md" \
		"operations.md" \
		"kubernetes.md" \
		"air-gapped.md" \
		"release-signing.md" \
		"production-hardening.md" \
		"reference/configuration.md" \
		"reference/capability-map.md" \
		"reference/api-contract-matrix.md" \
		"reference/openapi.md" \
		"openapi/index.html" \
		"reference/vulnerability-decisions.md" \
		"reference/observability.md" \
		"reference/capacity-and-failures.md" \
			"reference/benchmark-results.md" \
			"reference/production-readiness.md" \
			"reference/production-readiness-traceability.md" \
			"reference/production-internal-exit-checklist.md" \
			"reference/production-readiness-audit-closeout.md" \
			"reference/production-internal-score.md" \
			"reference/persistence-decomposition.md" \
		"reference/production-exit-review.md" \
		"reference/stable-v0.1.0-exit-criteria.md" \
		"reference/hardened-reference-deployment.md" \
		"reference/ha-strategy.md" \
		"reference/external-controls-matrix.md" \
		"reference/production-gate-troubleshooting.md" \
		"reference/upgrade-compatibility-policy.md" \
		"reference/release-candidate.md" \
		"reference/release-evidence-index.md" \
		"reference/release-notes-template.md" \
		"reference/release-notes-v0.1.0-rc.1.md" \
		"reference/maintainer-review-policy.md" \
		"reference/roadmap.md" \
		"reference/worker-outbox.md" \
		"reference/release-validation.md" \
		"reference/upload-manifest.md" \
		"runbooks/key-rotation.md" \
		"runbooks/object-store-recovery.md" \
		"collectors/source-snapshots.md" \
		"collectors/supply-chain.md" \
		"github-actions/end-to-end-release-evidence.md" \
		"github-actions/quickstart-release-evidence.yml" \
		"github-actions/release-evidence-workflow.yml" \
		"github-actions/upload-build/action.yml" \
		"gitlab/evydence-release-evidence.gitlab-ci.yml" \
		"sdk/README.md" \
		"sdk/quickstarts.md" \
		"architecture.md" \
		"explanation/trust-model.md"; do \
		grep -F "$$path" docs/README.md >/dev/null || { echo "docs/README.md missing link to $$path"; exit 1; }; \
	done
	@python3 -c 'import json,re,sys; from pathlib import Path; spec=json.loads(Path("openapi.yaml").read_text()); doc=Path("docs/api.md").read_text(); openapi=set(spec["paths"]); catalog=set(re.findall(r"`(/v1/[^`]+)`", doc)); missing=sorted(openapi-catalog); extra=sorted(catalog-openapi); [print("docs/api.md missing OpenAPI path: "+p) for p in missing]; [print("docs/api.md lists non-OpenAPI path: "+p) for p in extra]; sys.exit(1 if missing or extra else 0)'
	@scripts/openapi_contract_matrix.py > /tmp/evydence-api-contract-matrix.md
	@cmp -s docs/reference/api-contract-matrix.md /tmp/evydence-api-contract-matrix.md
	@grep -F 'case "release"' cmd/evydence/main.go >/dev/null
	@grep -F 'case "import-bundle"' cmd/evydence/main.go >/dev/null
	@grep -F 'case "upload"' cmd/evydence/main.go >/dev/null
	@grep -F './dist/evydence release manifest' docs/release-signing.md >/dev/null
	@grep -F './dist/evydence release keygen' docs/release-signing.md >/dev/null
	@grep -F './dist/evydence release sign' docs/release-signing.md >/dev/null
	@grep -F './dist/evydence release verify' docs/release-signing.md >/dev/null
	@grep -F './dist/evydence release manifest' docs/air-gapped.md >/dev/null
	@grep -F './evydence release verify' docs/air-gapped.md >/dev/null
	@grep -F './evydence import-bundle upload' docs/air-gapped.md >/dev/null
	@test -x scripts/public_release_verify.sh
	@grep -F 'This CVE appears in your SBOM. Are you affected, why, who approved it, and' docs/tutorials/evaluate-in-10-minutes.md >/dev/null
	@grep -F 'sample-customer-package-manifest.json' docs/tutorials/evaluate-in-10-minutes.md >/dev/null
	@grep -F 'site/package-viewer/index.html' docs/tutorials/evaluate-in-10-minutes.md >/dev/null
	@grep -F 'examples/end-to-end-release-evidence/run-local-demo.sh' docs/tutorials/evaluate-in-10-minutes.md >/dev/null
	@grep -F 'Evaluate Evydence in 10 minutes' README.md docs/README.md >/dev/null
	@grep -F 'Customer CVE review demo' README.md docs/README.md docs/tutorials/customer-cve-review-demo.md >/dev/null
	@grep -F 'The core buyer question is' README.md >/dev/null
	@grep -F 'Buyer evaluation overview' README.md docs/README.md >/dev/null
	@grep -F 'Operator overview' README.md docs/README.md >/dev/null
	@grep -F 'OpenAPI reference' README.md >/dev/null
	@grep -F 'Rendered OpenAPI docs' README.md docs/README.md docs/reference/openapi.md >/dev/null
	@grep -F 'site/marketing/public/api/index.html' docs/reference/openapi.md >/dev/null
	@grep -F 'SDK quickstarts' docs/README.md docs/sdk/README.md docs/sdk/quickstarts.md >/dev/null
	@grep -F 'Problem Details' docs/sdk/quickstarts.md >/dev/null
	@grep -F 'Idempotency-Key' docs/sdk/quickstarts.md >/dev/null
	@grep -F 'dist/evydence package verify' docs/sdk/quickstarts.md >/dev/null
	@grep -F 'Install and operate' README.md >/dev/null
	@grep -F 'Fastest Buyer Path' docs/buyer-overview.md >/dev/null
	@grep -F 'Primary Operator Path' docs/operator-overview.md >/dev/null
	@grep -F 'Capability map' README.md docs/README.md >/dev/null
	@grep -F 'Production Check' README.md docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'coverage.out' README.md docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'release-check-summary.txt' README.md docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'Production readiness traceability' docs/README.md >/dev/null
	@grep -F 'Traceability Matrix' docs/reference/production-readiness-traceability.md >/dev/null
	@grep -F 'Unmapped Internal Findings' docs/reference/production-readiness-traceability.md >/dev/null
	@grep -F 'External Blockers' docs/reference/production-readiness-traceability.md >/dev/null
	@grep -F 'Internal production-readiness exit checklist' docs/README.md >/dev/null
	@grep -F 'Required Internal State' docs/reference/production-internal-exit-checklist.md >/dev/null
	@grep -F 'make production-check' docs/reference/production-internal-exit-checklist.md >/dev/null
	@grep -F 'every external item must have a current owner and status' docs/reference/production-internal-exit-checklist.md >/dev/null
	@grep -F 'fresh production-readiness audit finds no new repo-local remediation' docs/reference/production-internal-exit-checklist.md >/dev/null
	@grep -F 'Production readiness audit closeout' docs/README.md >/dev/null
	@grep -F 'Fresh Audit Result' docs/reference/production-readiness-audit-closeout.md >/dev/null
	@grep -F 'found no new repo-local remediation' docs/reference/production-readiness-audit-closeout.md >/dev/null
	@grep -F 'Production-usable with caveats' docs/reference/production-readiness-audit-closeout.md >/dev/null
	@grep -F 'Highest achievable internal score' docs/README.md >/dev/null
	@grep -F 'Overall | 8.3/10' docs/reference/production-internal-score.md >/dev/null
	@grep -F 'Remaining External Blockers' docs/reference/production-internal-score.md >/dev/null
	@grep -F 'controlled self-hosted production candidate' docs/reference/production-internal-score.md >/dev/null
	@! grep -R -F '.audits/' README.md docs
	@test -x scripts/production_benchmark_check.sh
	@grep -F 'production_benchmark_check.sh' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'tmp/production-benchmark/production-benchmark-summary.json' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'local regression benchmark' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'Implemented-But-Partial Areas' docs/reference/capability-map.md >/dev/null
	@grep -F 'VEX/manual' README.md >/dev/null
	@test -f docs/assets/package-viewer-preview.svg
	@test -f docs/assets/package-viewer-desktop.png
	@test -f docs/assets/package-viewer-mobile.png
	@grep -F 'package-viewer-preview.svg' docs/how-to/view-packages.md >/dev/null
	@grep -F 'package-viewer-desktop.png' docs/how-to/view-packages.md >/dev/null
	@grep -F 'package-viewer-mobile.png' docs/how-to/view-packages.md >/dev/null
	@grep -F 'scripts/capture_package_viewer_screenshots.sh' docs/how-to/view-packages.md >/dev/null
	@grep -F 'report.html' docs/reference/customer-package-manifest.md docs/how-to/view-packages.md >/dev/null
	@grep -F 'Redaction Leakage Guard' docs/reference/customer-package-manifest.md >/dev/null
	@grep -F 'reviewer_checklist' docs/reference/customer-package-manifest.md >/dev/null
	@grep -F 'make restore-rehearsal-check' docs/runbooks/backup-restore.md >/dev/null
	@grep -F 'API key' docs/runbooks/key-rotation.md >/dev/null
	@grep -F 'Tenant signing key' docs/runbooks/key-rotation.md >/dev/null
	@grep -F 'make restore-rehearsal-check' docs/runbooks/object-store-recovery.md >/dev/null
	@grep -F 'Do not regenerate or overwrite historical evidence' docs/runbooks/object-store-recovery.md >/dev/null
	@test -f docs/how-to/pilot-deployment-checklist.md
	@grep -F 'Required: external PostgreSQL' docs/how-to/pilot-deployment-checklist.md >/dev/null
	@grep -F 'external controls matrix' docs/reference/production-readiness.md docs/kubernetes.md docs/how-to/pilot-deployment-checklist.md >/dev/null
	@grep -F 'Production gate troubleshooting' docs/reference/production-readiness.md docs/reference/release-validation.md docs/README.md >/dev/null
	@grep -F 'Stable v0.1.0 exit criteria' docs/reference/production-readiness.md docs/reference/release-validation.md docs/reference/production-exit-review.md docs/reference/roadmap.md docs/README.md >/dev/null
	@grep -F 'Upgrade and compatibility policy' docs/runbooks/upgrade.md docs/README.md >/dev/null
	@grep -F 'Release candidates may still make breaking API or schema changes' docs/reference/upgrade-compatibility-policy.md >/dev/null
	@grep -F 'make migration-compatibility-check' docs/reference/upgrade-compatibility-policy.md >/dev/null
	@grep -F 'not legal compliance proof' docs/reference/stable-v0.1.0-exit-criteria.md >/dev/null
	@grep -F 'make public-release-verify TAG=<v0.1.0-rc.N>' docs/reference/stable-v0.1.0-exit-criteria.md >/dev/null
	@grep -F 'one API writer replica' docs/reference/stable-v0.1.0-exit-criteria.md >/dev/null
	@grep -F '!.production.env.example' .gitignore >/dev/null
	@grep -F 'ENV=production' .production.env.example >/dev/null
	@grep -Fx 'EVYDENCE_DATABASE_URL=' .production.env.example >/dev/null
	@grep -Fx 'EVYDENCE_API_KEY_PEPPER=' .production.env.example >/dev/null
	@grep -F 'EVYDENCE_OBJECT_STORE=s3' .production.env.example >/dev/null
	@grep -F 'EVYDENCE_SIGNING_KEY_MODE=external' .production.env.example >/dev/null
	@grep -F 'EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE' .production.env.example >/dev/null
	@grep -F 'EVYDENCE_PRINT_BOOTSTRAP_SECRET=false' .production.env.example >/dev/null
	@! grep -F 'change-me' .production.env.example >/dev/null
	@grep -F 'Telemetry and diagnostics' .production.env.example >/dev/null
	@grep -F 'Do not export raw evidence payloads' .production.env.example >/dev/null
	@grep -F '.production.env.example' docs/reference/configuration.md docs/how-to/install-and-operate.md docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'single API writer replica' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'scalable worker replicas' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'external PostgreSQL' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'external S3/MinIO-compatible object storage' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'request body limits' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'make production-check' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'not legal compliance proof' docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'Hardened reference deployment' docs/README.md docs/operator-overview.md docs/kubernetes.md docs/production-hardening.md docs/reference/production-readiness.md docs/reference/source-of-truth.md >/dev/null
	@grep -F 'single-writer self-hosted appliance' docs/reference/ha-strategy.md >/dev/null
	@grep -F 'Multi-writer API high availability is not supported' docs/reference/ha-strategy.md >/dev/null
	@grep -F 'Before Multi-Writer API Is Supported' docs/reference/ha-strategy.md >/dev/null
	@grep -F 'EVYDENCE_API_WRITER_REPLICAS=1' docs/reference/ha-strategy.md >/dev/null
	@grep -F 'HA strategy' docs/README.md docs/operator-overview.md docs/kubernetes.md docs/reference/production-readiness.md docs/reference/capacity-and-failures.md docs/reference/hardened-reference-deployment.md docs/reference/roadmap.md docs/reference/source-of-truth.md >/dev/null
	@grep -F 'Persistence decomposition inventory' docs/README.md docs/reference/production-readiness.md docs/reference/capability-map.md docs/reference/ha-strategy.md docs/reference/source-of-truth.md >/dev/null
	@grep -F 'scripts/persistence_decomposition_inventory.py --write' docs/reference/persistence-decomposition.md >/dev/null
	@grep -F 'Remaining Broad Relational-State Mutations' docs/reference/persistence-decomposition.md >/dev/null
	@grep -F 'make persistence-decomposition-check' docs/reference/persistence-decomposition.md >/dev/null
	@grep -F 'Required: object paths are tenant-prefixed' docs/how-to/pilot-deployment-checklist.md >/dev/null
	@grep -F 'Required: public API access is behind TLS' docs/how-to/pilot-deployment-checklist.md >/dev/null
	@test -f docs/commercial/design-partner-pilot.md
	@grep -F 'AGPL-3.0-only' docs/commercial/design-partner-pilot.md >/dev/null
	@grep -F 'Non-Deliverables' docs/commercial/design-partner-pilot.md >/dev/null
	@test -f docs/commercial/product-landing-copy.md
	@grep -F 'One-Sentence Pitch' docs/commercial/product-landing-copy.md >/dev/null
	@grep -F 'Why Self-Hosted' docs/commercial/product-landing-copy.md >/dev/null
	@grep -F 'Pilot CTA' docs/commercial/product-landing-copy.md >/dev/null
	@grep -F 'Paid Readiness Offer' docs/commercial/product-landing-copy.md >/dev/null
	@grep -F 'Release evidence readiness review' docs/commercial/product-landing-copy.md >/dev/null
	@test -f docs/commercial/category-comparison.md
	@grep -F 'Vulnerability scanners' docs/commercial/category-comparison.md >/dev/null
	@grep -F 'SBOM inventory tools' docs/commercial/category-comparison.md >/dev/null
	@grep -F 'Trust centers' docs/commercial/category-comparison.md >/dev/null
	@grep -F 'Dependency-Track' docs/commercial/category-comparison.md README.md docs/README.md >/dev/null
	@grep -F 'GUAC' docs/commercial/category-comparison.md README.md site/marketing/src/data/site.ts >/dev/null
	@grep -F 'OpenVEX tooling' docs/commercial/category-comparison.md >/dev/null
	@grep -F 'Vanta, Drata' docs/commercial/category-comparison.md README.md site/marketing/src/data/site.ts >/dev/null
	@grep -F 'Internal scripts, spreadsheets, object storage, and ad hoc databases' docs/commercial/category-comparison.md >/dev/null
	@grep -F 'release upload-evidence' docs/how-to/integrate-ci.md >/dev/null
	@grep -F 'Tool-specific integration templates' docs/README.md docs/how-to/integrate-ci.md docs/integrations/tool-templates.md >/dev/null
	@grep -F 'syft dir:.' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'grype dir:.' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'trivy fs --format json' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'Dependency-Track is adjacent inventory' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'Jira links are metadata' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'EVYDENCE_OBJECT_STORE=s3' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'Default repository checks do not call Syft, Grype, Trivy, Dependency-Track, Jira, GitHub, GitLab, S3, or MinIO' docs/integrations/tool-templates.md >/dev/null
	@grep -F 'End-to-end GitHub Actions release evidence guide' docs/how-to/integrate-ci.md docs/README.md docs/github-actions/end-to-end-release-evidence.md >/dev/null
	@grep -F 'least-privilege' docs/github-actions/end-to-end-release-evidence.md >/dev/null
	@grep -F 'do not make live GitHub API calls' docs/github-actions/end-to-end-release-evidence.md >/dev/null
	@grep -F 'EVYDENCE_API_KEY' docs/github-actions/end-to-end-release-evidence.md >/dev/null
	@grep -F 'release-readiness.json' docs/github-actions/end-to-end-release-evidence.md docs/github-actions/release-evidence-workflow.yml >/dev/null
	@grep -F 'upload-output.txt' docs/github-actions/end-to-end-release-evidence.md docs/github-actions/release-evidence-workflow.yml >/dev/null
	@grep -F 'actions/upload-artifact@v4' docs/github-actions/release-evidence-workflow.yml >/dev/null
	@grep -F 'make local-ci-simulation-check' docs/how-to/integrate-ci.md examples/end-to-end-release-evidence/README.md >/dev/null
	@grep -F -- '--dry-run' docs/how-to/integrate-ci.md >/dev/null
	@grep -F 'upload validate-manifest' docs/how-to/integrate-ci.md >/dev/null
	@grep -F 'evydence-upload-manifest.v1.0.0' docs/reference/upload-manifest.md schemas/upload-manifest.v1.schema.json >/dev/null
	@grep -F 'dist/evydence github-actions upload-build' docs/github-actions/quickstart-release-evidence.yml >/dev/null
	@grep -F 'upload validate-manifest' docs/github-actions/quickstart-release-evidence.yml >/dev/null
	@grep -F 'scripts/github_release_evidence_manifest.py' docs/github-actions/quickstart-release-evidence.yml >/dev/null
	@grep -F '/v1/reports/release-readiness' docs/github-actions/quickstart-release-evidence.yml >/dev/null
	@grep -F 'dist/evydence github-actions upload-build' docs/github-actions/release-evidence-workflow.yml >/dev/null
	@grep -F 'go run ./cmd/evydence "$${args[@]}"' docs/github-actions/upload-build/action.yml >/dev/null
	@grep -F 'cat > evydence-upload-manifest.json' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F 'artifact.digest' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F 'upload validate-manifest' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F -- '--manifest evydence-upload-manifest.json' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F 'make production-check' .github/workflows/ci.yml >/dev/null
	@grep -F 'tmp/black-box-release-artifact/black-box-release-artifact-summary.json' .github/workflows/ci.yml >/dev/null
	@grep -F 'black-box release-style binary evidence' docs/reference/release-validation.md >/dev/null
	@grep -F 'make black-box-release-artifact-check' docs/reference/production-readiness.md docs/reference/release-validation.md >/dev/null
	@grep -F 'make production-check' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'EVYDENCE_RELEASE_PUBLISH_TOKEN' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'scripts/release_candidate_package.sh' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'evydence-release-manifest.sig.json' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'evydence-release-manifest.sig alias' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'gh release create' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F -- '--repo "$${repo}"' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'contents: read' .github/workflows/release-artifacts.yml >/dev/null
	@! grep -F 'contents: write' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'Container Image' .github/workflows/container-image.yml >/dev/null
	@grep -F 'EVYDENCE_GHCR_PUBLISH_TOKEN' .github/workflows/container-image.yml >/dev/null
	@! grep -F 'packages: write' .github/workflows/container-image.yml >/dev/null
	@grep -F 'evydence-container-image-manifest.json' .github/workflows/container-image.yml >/dev/null
	@grep -F 'cosign-keyless' .github/workflows/container-image.yml >/dev/null
	@grep -F 'ghcr.io/aatuh/evydence' README.md >/dev/null
	@grep -F 'ghcr.io/aatuh/evydence' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'ghcr.io/aatuh/evydence' docs/kubernetes.md >/dev/null
	@grep -F 'ghcr.io/aatuh/evydence' deploy/airgap/manifest.yaml >/dev/null
	@grep -F 'sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888' docs/reference/release-evidence-index.md deploy/airgap/manifest.yaml >/dev/null
	@grep -F 'cosign verify' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'github/codeql-action/init@7211b7c8077ea37d8641b6271f6a365a22a5fbfa' .github/workflows/codeql.yml >/dev/null
	@grep -F 'security-and-quality' .github/workflows/codeql.yml >/dev/null
	@grep -F 'Controlled self-hosted production candidate' docs/reference/release-candidate.md >/dev/null
	@grep -F 'Release evidence index' docs/reference/release-candidate.md >/dev/null
	@grep -F 'evydence-release-manifest.sig.json' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'evydence-release-manifest.sig' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'evydence-release-provenance.intoto.jsonl' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'CODEOWNERS' docs/reference/maintainer-review-policy.md >/dev/null
	@grep -F 'OpenSSF Scorecard and Scorecard SARIF remain' docs/reference/maintainer-review-policy.md >/dev/null
	@grep -F 'one API writer replica' docs/reference/roadmap.md >/dev/null
	@grep -F 'Controlled self-hosted production candidate' docs/reference/release-notes-template.md >/dev/null
	@grep -F 'not legal compliance proof' docs/reference/release-notes-template.md >/dev/null
	@grep -F 'Controlled self-hosted production candidate' docs/reference/release-notes-v0.1.0-rc.1.md >/dev/null
	@grep -F 'not legal compliance proof' docs/reference/release-notes-v0.1.0-rc.1.md >/dev/null
	@grep -F 'Use one API writer replica' docs/reference/release-candidate.md >/dev/null
	@grep -F 'make release-asset-smoke-check' docs/reference/release-validation.md docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'checksum, signature, missing-asset, and package-identity mismatch' docs/reference/release-validation.md >/dev/null
	@grep -F 'tampered manifest failure' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'private security intake' SECURITY.md >/dev/null
	@! grep -R -i "automatically compliant\|certified secure\|legally sufficient\|SBOM is complete\|all vulnerabilities detected\|scanner findings are authoritative\|regulator-ready without review" README.md docs
	@grep -F 'make marketing-site-production-check' docs/how-to/publish-marketing-site.md >/dev/null
	@grep -F 'G-XC2ESEHQ3W' docs/how-to/publish-marketing-site.md >/dev/null
	@grep -F 'evydence.app' docs/how-to/publish-marketing-site.md >/dev/null

deploy-check: ## Validate deployment and air-gap skeletons exist
	@test -f compose.production-like.yml
	@test -f deploy/helm/evydence/Chart.yaml
	@test -f deploy/helm/evydence/values.yaml
	@test -f deploy/helm/evydence/templates/deployment-api.yaml
	@test -f deploy/helm/evydence/templates/deployment-worker.yaml
	@test -f deploy/helm/evydence/templates/networkpolicy.yaml
	@test -f deploy/airgap/manifest.yaml
	@test -f deploy/observability/prometheus-rules.yaml
	@test -f deploy/observability/grafana-dashboard.json
	@grep -F 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229' compose.production-like.yml >/dev/null
	@grep -F 'minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e' compose.production-like.yml >/dev/null
	@grep -F 'minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727' compose.production-like.yml >/dev/null
	@! grep -E 'image:[[:space:]]+[^$$]*:latest' compose.production-like.yml >/dev/null
	@grep -F 'tag: ""' deploy/helm/evydence/values.yaml >/dev/null
	@grep -F 'replicas: 1' deploy/helm/evydence/values.yaml >/dev/null
	@grep -F 'writerMode: single' deploy/helm/evydence/values.yaml >/dev/null
	@grep -F 'EVYDENCE_API_WRITER_MODE' deploy/helm/evydence/templates/configmap.yaml >/dev/null
	@grep -F 'EVYDENCE_API_WRITER_REPLICAS' deploy/helm/evydence/templates/configmap.yaml >/dev/null
	@grep -F 'runAsNonRoot: true' deploy/helm/evydence/values.yaml >/dev/null
	@grep -F 'allowPrivilegeEscalation: false' deploy/helm/evydence/values.yaml >/dev/null
	@grep -F 'required "image.tag is required' deploy/helm/evydence/templates/deployment-api.yaml >/dev/null
	@grep -F 'required "image.tag is required' deploy/helm/evydence/templates/deployment-worker.yaml >/dev/null
	@grep -F 'evydence-worker' deploy/helm/evydence/templates/deployment-worker.yaml >/dev/null
	@grep -F 'healthcheck' deploy/helm/evydence/values.yaml >/dev/null
	@grep -F 'single API writer replica' docs/kubernetes.md >/dev/null
	@grep -F 'Hardened reference deployment' docs/kubernetes.md docs/reference/hardened-reference-deployment.md >/dev/null
	@grep -F 'HA strategy' docs/kubernetes.md docs/reference/ha-strategy.md >/dev/null
	@grep -F 'EVYDENCE_API_WRITER_MODE: single' compose.production-like.yml >/dev/null
	@grep -F 'EVYDENCE_PRINT_BOOTSTRAP_SECRET: "false"' compose.production-like.yml >/dev/null
	@grep -F 'evydence-migrate ./cmd/evydence-migrate' Dockerfile >/dev/null
	@grep -F 'entrypoint: ["evydence-migrate"]' compose.production-like.yml >/dev/null
	@grep -F 'entrypoint: ["evydence-worker"]' compose.production-like.yml >/dev/null

sdk-check: ## Validate SDK helper and generated route-catalog coverage against OpenAPI
	@test -f sdk/go/evydence/client.go
	@test -f sdk/typescript/client.ts
	@test -f sdk/python/evydence_client.py
	@test -f sdk/openapi-route-catalog.json
	@python3 scripts/sdk_check.py

demo-check: ## Validate checked end-to-end evidence demo fixtures
	@test -x examples/end-to-end-release-evidence/run-local-demo.sh
	@test -x examples/customer-cve-review-demo/run-demo.sh
	@test -x scripts/local_ci_simulation_check.sh
	@test -x scripts/reviewer_package_workflow_check.sh
	@test -x scripts/black_box_release_artifact_check.sh
	@test -f examples/end-to-end-release-evidence/README.md
	@test -f examples/customer-cve-review-demo/README.md
	@test -f examples/customer-cve-review-demo/customer-cve-review-story.json
	@test -f examples/customer-cve-review-demo/expected-verification-output.txt
	@test -f examples/end-to-end-release-evidence/release-evidence-manifest.json
	@test -f examples/end-to-end-release-evidence/sample-readiness-report.json
	@test -f examples/end-to-end-release-evidence/sample-security-summary.json
	@test -f examples/end-to-end-release-evidence/sample-customer-package-manifest.json
	@test -f examples/end-to-end-release-evidence/sample-customer-package-manifest.sha256
	@test -f examples/end-to-end-release-evidence/sample-customer-package.zip
	@test -f examples/end-to-end-release-evidence/sample-audit-chain-verification.json
	@python3 -c 'import json, pathlib; [json.loads(path.read_text()) for path in pathlib.Path("examples/end-to-end-release-evidence").glob("*.json")]'
	@cd examples/end-to-end-release-evidence && sha256sum -c sample-customer-package-manifest.sha256 >/dev/null
	@$(GO) run ./cmd/evydence package verify --archive examples/end-to-end-release-evidence/sample-customer-package.zip --expected-package-id csp_example --expected-product-id prod_example --expected-release-id rel_example >/dev/null
	@grep -F '/v1/reports/release-readiness' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F '/security-summary' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F '/v1/audit-chain/verify' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F '/v1/customer-packages' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F 'not legal' examples/end-to-end-release-evidence/README.md >/dev/null
	@grep -F 'CVE-2026-0002' examples/customer-cve-review-demo/customer-cve-review-story.json examples/customer-cve-review-demo/README.md docs/tutorials/customer-cve-review-demo.md >/dev/null
	@grep -F 'approved_for_customer_package' examples/customer-cve-review-demo/customer-cve-review-story.json examples/customer-cve-review-demo/README.md docs/tutorials/customer-cve-review-demo.md >/dev/null
	@grep -F 'not legal compliance proof' examples/customer-cve-review-demo/README.md docs/tutorials/customer-cve-review-demo.md >/dev/null
	@grep -F 'reviewer_checklist' examples/end-to-end-release-evidence/sample-customer-package-manifest.json >/dev/null
	@grep -F 'escalation_path' examples/end-to-end-release-evidence/sample-customer-package-manifest.json >/dev/null
	@grep -F 'sbom_component_purl' examples/end-to-end-release-evidence/sample-customer-package-manifest.json >/dev/null
	@scripts/reviewer_package_workflow_check.sh
	@$(MAKE) customer-cve-review-demo-check

customer-cve-review-demo-check: ## Validate deterministic customer CVE review demo
	@examples/customer-cve-review-demo/run-demo.sh >/dev/null

local-ci-simulation-check: ## Run local one-command CI evidence simulation without external services
	@scripts/local_ci_simulation_check.sh

reviewer-package-workflow-check: ## Validate offline reviewer package verification, extraction, and report inspection
	@scripts/reviewer_package_workflow_check.sh

black-box-demo-check: ## Run live PostgreSQL black-box API/worker demo; requires EVYDENCE_TEST_DATABASE_URL
	@scripts/black_box_demo_check.sh

black-box-release-artifact-check: ## Run live PostgreSQL black-box demo against release-style local binaries
	@scripts/black_box_release_artifact_check.sh

benchmark-check: ## Run the checked app-layer release evidence benchmark
	@$(GO) test ./internal/app -bench BenchmarkReleaseEvidenceIngestion -benchtime=100x -run '^$$' -benchmem
	@if [ -n "$$EVYDENCE_TEST_DATABASE_URL" ]; then scripts/production_benchmark_check.sh; else echo "EVYDENCE_TEST_DATABASE_URL not set; skipping production black-box benchmark"; fi
	@grep -F 'BenchmarkReleaseEvidenceIngestion' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'production_benchmark_check.sh' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'evydence-production-benchmark.v1.0.0' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'API writer replicas: `1`' docs/reference/capacity-and-failures.md >/dev/null

package-viewer-check: ## Validate local package viewer and walkthrough
	@test -f site/package-viewer/index.html
	@test -f docs/how-to/view-packages.md
	@test -x scripts/capture_package_viewer_screenshots.sh
	@test -f docs/assets/package-viewer-desktop.png
	@test -f docs/assets/package-viewer-mobile.png
	@test -f docs/assets/reviewer-journey.svg
	@grep -F 'Load bundled demo' site/package-viewer/index.html >/dev/null
	@grep -F 'textContent' site/package-viewer/index.html >/dev/null
	@! grep -F 'innerHTML' site/package-viewer/index.html >/dev/null
	@grep -F 'Release Summary' site/package-viewer/index.html >/dev/null
	@grep -F 'Reviewer Dossier' site/package-viewer/index.html docs/how-to/view-packages.md >/dev/null
	@grep -F 'read-only package scope' site/package-viewer/index.html docs/how-to/view-packages.md >/dev/null
	@grep -F 'Package verification result' site/package-viewer/index.html >/dev/null
	@grep -F 'Offline verification instructions' site/package-viewer/index.html >/dev/null
	@grep -F 'evydence package verify' site/package-viewer/index.html docs/how-to/view-packages.md >/dev/null
	@grep -F 'Manifest Summary And Proof' site/package-viewer/index.html docs/how-to/view-packages.md >/dev/null
	@grep -F 'Evidence Link Status' site/package-viewer/index.html docs/how-to/view-packages.md >/dev/null
	@grep -F 'Package Verification Result' site/package-viewer/index.html >/dev/null
	@grep -F 'Signed release bundle material' site/package-viewer/index.html docs/how-to/view-packages.md >/dev/null
	@grep -F 'limitation/non-claim copy' docs/how-to/view-packages.md >/dev/null
	@grep -F 'Vulnerability / VEX Decisions' site/package-viewer/index.html >/dev/null
	@grep -F 'Verification Status' site/package-viewer/index.html >/dev/null
	@grep -F 'Reviewer checklist' site/package-viewer/index.html >/dev/null
	@grep -F 'reviewer_checklist' site/package-viewer/index.html >/dev/null
	@grep -F 'review_due_at' site/package-viewer/index.html >/dev/null
	@grep -F 'sbom_component_purl' site/package-viewer/index.html >/dev/null
	@grep -F 'examples/end-to-end-release-evidence/sample-customer-package-manifest.json' docs/how-to/view-packages.md >/dev/null
	@grep -F 'package-viewer-desktop.png' docs/how-to/view-packages.md >/dev/null
	@grep -F 'package-viewer-mobile.png' docs/how-to/view-packages.md >/dev/null
	@grep -F 'not package verification evidence' docs/how-to/view-packages.md >/dev/null
	@grep -F 'reviewer-journey.svg' docs/how-to/view-packages.md >/dev/null
	@grep -F 'hash/signature verification' docs/how-to/view-packages.md >/dev/null
	@grep -F 'Release Summary' docs/assets/reviewer-journey.svg >/dev/null
	@grep -F 'VEX Decisions' docs/assets/reviewer-journey.svg >/dev/null
	@grep -F 'Evidence Contents' docs/assets/reviewer-journey.svg >/dev/null
	@grep -F 'Verification Status' docs/assets/reviewer-journey.svg >/dev/null
	@grep -F 'Gaps' docs/assets/reviewer-journey.svg >/dev/null
	@grep -F 'Limitations' docs/assets/reviewer-journey.svg >/dev/null

release-asset-smoke-check: ## Verify local release asset checksums, signature, package verification, and failure cases
	@scripts/release_asset_smoke_check.sh

marketing-site-check: ## Build and validate the static marketing site
	@npm --prefix site/marketing run check

marketing-site-production-check: ## Build and validate the marketing site for evydence.app
	@PUBLIC_SITE_URL=https://evydence.app PUBLIC_SITE_BASE=/ PUBLIC_GA_MEASUREMENT_ID=G-XC2ESEHQ3W npm --prefix site/marketing run check

restore-rehearsal-check: ## Run repository-owned backup/restore rehearsal tests
	@$(GO) test ./internal/app -run TestBackupRestoreRehearsalPreservesLedgerAndObjectPayloads -count=1
	@$(GO) test ./internal/adapters/postgres -run TestPostgresBackupRestoreRehearsalPreservesLedgerAndObjects -count=1

fast-check: ## Run non-mutating fast validation
	@$(MAKE) test
	@$(MAKE) fuzz-smoke
	@$(MAKE) openapi-check
	@$(MAKE) openapi-precision-check
	@$(MAKE) docs-check
	@$(MAKE) deploy-check
	@$(MAKE) sdk-check
	@$(MAKE) demo-check
	@$(MAKE) package-viewer-check

finalize: ## Thorough validity check
	@$(MAKE) fmt
	@$(MAKE) test
	@$(MAKE) openapi-check
	@$(MAKE) openapi-precision-check
	@$(MAKE) docs-check
	@$(MAKE) deploy-check
	@$(MAKE) sdk-check
	@$(MAKE) demo-check
	@$(MAKE) package-viewer-check

release-acceptance: ## Run deterministic release metadata acceptance checks
	@scripts/release_acceptance.sh
	@$(MAKE) release-asset-smoke-check

release-check: ## Release validation with security, race, and configured live integration gates
	@$(MAKE) finalize
	@$(MAKE) release-acceptance
	@$(MAKE) lint
	@$(MAKE) gosec
	@$(MAKE) vuln
	@$(MAKE) test-race
	@$(MAKE) live-postgres-check
	@$(MAKE) postgres-integration-test
	@mkdir -p tmp
	@{ \
		echo "evydence release-check summary"; \
		echo "generated_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		echo "finalize=passed"; \
		echo "lint=passed"; \
		echo "gosec=passed"; \
		echo "govulncheck=passed"; \
		echo "race=passed"; \
		if [ -n "$$EVYDENCE_TEST_DATABASE_URL" ]; then \
			echo "live_postgres=passed"; \
			echo "postgres_integration=passed"; \
		else \
			echo "live_postgres=skipped EVYDENCE_TEST_DATABASE_URL unset"; \
			echo "postgres_integration=skipped EVYDENCE_TEST_DATABASE_URL unset"; \
		fi; \
	} | tee tmp/release-check-summary.txt

production-check: ## Strict self-hosted production readiness gate; requires live PostgreSQL and coverage threshold
	@scripts/production_check.sh

release-candidate-check: ## Build and validate a signed release-candidate package with explicit TAG=vX.Y.Z-rc.N
	@scripts/release_candidate_package.sh "$(TAG)"

public-release-verify: ## Download and verify public release assets with TAG=vX.Y.Z-rc.N
	@scripts/public_release_verify.sh "$(TAG)"

migration-compatibility-check: ## Verify every committed migration prefix upgrades to current schema
	@$(GO) test ./internal/adapters/postgres -run TestMigrationCompatibilityFromEveryCommittedState -count=1

release-check-local-postgres: ## Start Compose Postgres, load .test.env or .test.env.example, and run release-check
	@docker compose up -d postgres
	@echo "waiting for compose postgres..."
	@for i in $$(seq 1 30); do \
		if docker compose exec -T postgres pg_isready -U "$${POSTGRES_USER:-evydence}" >/dev/null 2>&1; then break; fi; \
		if [ "$$i" = "30" ]; then echo "postgres did not become ready"; exit 1; fi; \
		sleep 1; \
	done
	@env_file=".test.env"; \
	if [ ! -f "$$env_file" ]; then env_file=".test.env.example"; fi; \
	echo "loading $$env_file for release-check-local-postgres"; \
	set -a; . "./$$env_file"; set +a; \
	$(MAKE) release-check

compose-up: ## Start local dependencies
	@docker compose up -d

compose-down: ## Stop local dependencies
	@docker compose down

migrate: ## Apply PostgreSQL migrations with EVYDENCE_DATABASE_URL
	@test -n "$$EVYDENCE_DATABASE_URL"
	@$(GO) run ./cmd/evydence-migrate

live-postgres-check: ## Verify PostgreSQL connectivity and migrations when EVYDENCE_TEST_DATABASE_URL is set
	@if [ -z "$$EVYDENCE_TEST_DATABASE_URL" ]; then echo "EVYDENCE_TEST_DATABASE_URL not set; skipping live postgres check"; exit 0; else EVYDENCE_DATABASE_URL="$$EVYDENCE_TEST_DATABASE_URL" $(GO) run ./cmd/evydence-migrate; fi

postgres-integration-test: ## Run Postgres-backed integration tests when EVYDENCE_TEST_DATABASE_URL is set
	@if [ -z "$$EVYDENCE_TEST_DATABASE_URL" ]; then echo "EVYDENCE_TEST_DATABASE_URL not set; skipping postgres integration tests"; exit 0; else $(GO) test ./internal/adapters/postgres ./internal/app -count=1; fi

clean: ## Clean local test artifacts
	@rm -f coverage.out
	@rm -rf tmp
