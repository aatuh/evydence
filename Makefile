GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

TOOLS := golangci-lint gosec govulncheck
GOLANGCI_LINT_VERSION ?= v2.11.4
GOSEC_VERSION ?= v2.25.0
GOVULNCHECK_VERSION ?= v1.2.0

TAG ?=

.PHONY: help tools fmt lint vuln gosec test test-race coverage coverage-check openapi-check openapi-precision-check meta-check docs-check deploy-check sdk-check demo-check black-box-demo-check benchmark-check package-viewer-check fast-check finalize release-acceptance release-check production-check release-candidate-check migration-compatibility-check release-check-local-postgres compose-up compose-down migrate live-postgres-check postgres-integration-test clean

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

test-race: ## Run race tests
	@$(GO) test ./... -race -count=1

coverage: ## Run tests with coverage
	@$(GO) test ./... -coverprofile=coverage.out
	@$(GO) tool cover -func=coverage.out

coverage-check: ## Enforce the production coverage threshold
	@scripts/coverage_check.sh

openapi.yaml: ## Generate committed OpenAPI source
	@$(GO) run ./cmd/openapi > openapi.yaml

openapi-check: openapi.yaml ## Validate OpenAPI generation and route contract tests
	@$(GO) test ./internal/adapters/httpapi -run 'TestRoutesValidateAndOpenAPIRenders'
	@$(GO) run ./cmd/openapi > /tmp/evydence-openapi.yaml
	@cmp -s openapi.yaml /tmp/evydence-openapi.yaml

openapi-precision-check: ## Enforce current OpenAPI precision floor and broad-route ceiling
	@python3 scripts/openapi_precision_check.py

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
	@test -f .github/workflows/codeql.yml
	@test -f .github/ISSUE_TEMPLATE.md
	@test -f .github/ISSUE_TEMPLATE/bug_report.yml
	@test -f .github/ISSUE_TEMPLATE/feature_request.yml
	@test -f .github/ISSUE_TEMPLATE/docs.yml
	@test -f .github/ISSUE_TEMPLATE/production_support.yml
	@test -f .github/pull_request_template.md
	@test -x scripts/release_acceptance.sh
	@test -x scripts/release_candidate_package.sh
	@test -x scripts/release_candidate_validate.sh
	@test -x scripts/release_evidence_metadata.py
	@grep -F 'GNU AFFERO GENERAL PUBLIC LICENSE' LICENSE >/dev/null
	@grep -F 'AGPL-3.0-only' COMMERCIAL.md >/dev/null
	@grep -F 'Commercial license exceptions' COMMERCIAL.md >/dev/null
	@grep -F 'contributor license agreement' CONTRIBUTING.md >/dev/null
	@grep -F 'raw evidence payloads' SECURITY.md >/dev/null
	@grep -F 'release evidence artifacts' SUPPORT.md >/dev/null
	@grep -F 'Security vulnerability' .github/ISSUE_TEMPLATE/config.yml >/dev/null
	@grep -F 'private vulnerability reporting' .github/ISSUE_TEMPLATE.md >/dev/null
	@grep -F 'tenant isolation' .github/pull_request_template.md >/dev/null
	@grep -F 'internal/app/' CODEOWNERS >/dev/null
	@grep -F 'docs/reference/release-evidence-index.md' CODEOWNERS >/dev/null
	@grep -F 'OpenSSF Scorecard' .github/workflows/scorecard.yml >/dev/null
	@grep -F 'ossf/scorecard-action@62b2cac7ed8198b15735ed49ab1e5cf35480ba46' .github/workflows/scorecard.yml >/dev/null
	@grep -F 'github/codeql-action/analyze@fee9466b8957867761f2d78f922ab084e3e2dd17' .github/workflows/codeql.yml >/dev/null
	@grep -F 'actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd' .github/workflows/ci.yml >/dev/null
	@grep -F 'actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c' .github/workflows/ci.yml >/dev/null
	@grep -F 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' .github/workflows/ci.yml >/dev/null
	@grep -F 'postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229' .github/workflows/ci.yml >/dev/null
	@grep -F 'Evydence fork' TRADEMARKS.md >/dev/null
	@grep -F 'Release evidence is not a certification' RELEASE_EVIDENCE.md >/dev/null
	@grep -F '.refs' .dockerignore >/dev/null
	@grep -F 'release-evidence' .dockerignore >/dev/null
	@grep -F 'backups' .dockerignore >/dev/null
	@grep -F '*.pem' .dockerignore >/dev/null

docs-check: meta-check ## Validate canonical docs exist and avoid forbidden product claims
	@test -f README.md
	@test -f docs/README.md
	@test -f docs/architecture.md
	@test -f docs/api.md
	@test -f docs/operations.md
	@test -f docs/kubernetes.md
	@test -f docs/air-gapped.md
	@test -f docs/release-signing.md
	@test -f docs/production-hardening.md
	@test -f docs/tutorials/getting-started.md
	@test -f docs/how-to/integrate-ci.md
	@test -f docs/how-to/install-and-operate.md
	@test -f docs/how-to/view-packages.md
	@test -f docs/reference/configuration.md
	@test -f docs/reference/api-contract-matrix.md
	@test -f docs/reference/openapi.md
	@test -f docs/reference/observability.md
	@test -f docs/reference/capacity-and-failures.md
	@test -f docs/reference/benchmark-results.md
	@test -f docs/reference/production-readiness.md
	@test -f docs/reference/production-exit-review.md
	@test -f docs/reference/release-candidate.md
	@test -f docs/reference/release-evidence-index.md
	@test -f docs/reference/release-notes-template.md
	@test -f docs/reference/release-notes-v0.1.0-rc.1.md
	@test -f docs/reference/maintainer-review-policy.md
	@test -f docs/reference/roadmap.md
	@test -f docs/reference/worker-outbox.md
	@test -f docs/reference/release-validation.md
	@test -f docs/explanation/trust-model.md
	@test -f docs/collectors/source-snapshots.md
	@test -f docs/collectors/supply-chain.md
	@test -f docs/github-actions/release-evidence-workflow.yml
	@test -f docs/github-actions/upload-build/action.yml
	@test -f docs/gitlab/evydence-release-evidence.gitlab-ci.yml
	@test -f .github/workflows/release-artifacts.yml
	@test -f .github/workflows/codeql.yml
	@test -f docs/sdk/README.md
	@for path in \
		"tutorials/getting-started.md" \
		"how-to/install-and-operate.md" \
		"how-to/view-packages.md" \
		"how-to/integrate-ci.md" \
		"api.md" \
		"operations.md" \
		"kubernetes.md" \
		"air-gapped.md" \
		"release-signing.md" \
		"production-hardening.md" \
		"reference/configuration.md" \
		"reference/api-contract-matrix.md" \
		"reference/openapi.md" \
		"reference/observability.md" \
		"reference/capacity-and-failures.md" \
		"reference/benchmark-results.md" \
		"reference/production-readiness.md" \
		"reference/production-exit-review.md" \
		"reference/release-candidate.md" \
		"reference/release-evidence-index.md" \
		"reference/release-notes-template.md" \
		"reference/release-notes-v0.1.0-rc.1.md" \
		"reference/maintainer-review-policy.md" \
		"reference/roadmap.md" \
		"reference/worker-outbox.md" \
		"reference/release-validation.md" \
		"collectors/source-snapshots.md" \
		"collectors/supply-chain.md" \
		"github-actions/release-evidence-workflow.yml" \
		"github-actions/upload-build/action.yml" \
		"gitlab/evydence-release-evidence.gitlab-ci.yml" \
		"sdk/README.md" \
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
	@grep -F 'dist/evydence github-actions upload-build' docs/github-actions/release-evidence-workflow.yml >/dev/null
	@grep -F 'go run ./cmd/evydence "$${args[@]}"' docs/github-actions/upload-build/action.yml >/dev/null
	@grep -F 'cat > evydence-upload-manifest.json' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F 'artifact.digest' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F -- '--manifest evydence-upload-manifest.json' docs/gitlab/evydence-release-evidence.gitlab-ci.yml >/dev/null
	@grep -F 'make production-check' .github/workflows/ci.yml >/dev/null
	@grep -F 'make production-check' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'scripts/release_candidate_package.sh' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'evydence-release-manifest.sig.json' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'gh release create' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'contents: read' .github/workflows/release-artifacts.yml >/dev/null
	@grep -F 'github/codeql-action/init@fee9466b8957867761f2d78f922ab084e3e2dd17' .github/workflows/codeql.yml >/dev/null
	@grep -F 'security-and-quality' .github/workflows/codeql.yml >/dev/null
	@grep -F 'Controlled self-hosted production candidate' docs/reference/release-candidate.md >/dev/null
	@grep -F 'Release evidence index' docs/reference/release-candidate.md >/dev/null
	@grep -F 'evydence-release-manifest.sig.json' docs/reference/release-evidence-index.md >/dev/null
	@grep -F 'CODEOWNERS' docs/reference/maintainer-review-policy.md >/dev/null
	@grep -F 'one API writer replica' docs/reference/roadmap.md >/dev/null
	@grep -F 'Controlled self-hosted production candidate' docs/reference/release-notes-template.md >/dev/null
	@grep -F 'not legal compliance proof' docs/reference/release-notes-template.md >/dev/null
	@grep -F 'Controlled self-hosted production candidate' docs/reference/release-notes-v0.1.0-rc.1.md >/dev/null
	@grep -F 'not legal compliance proof' docs/reference/release-notes-v0.1.0-rc.1.md >/dev/null
	@grep -F 'Use one API writer replica' docs/reference/release-candidate.md >/dev/null
	@grep -F 'private security intake' SECURITY.md >/dev/null
	@! grep -R -i "automatically compliant\|certified secure\|legally sufficient\|SBOM is complete\|all vulnerabilities detected\|scanner findings are authoritative\|regulator-ready without review" README.md docs

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
	@test -f examples/end-to-end-release-evidence/README.md
	@test -f examples/end-to-end-release-evidence/release-evidence-manifest.json
	@test -f examples/end-to-end-release-evidence/sample-readiness-report.json
	@test -f examples/end-to-end-release-evidence/sample-customer-package-manifest.json
	@test -f examples/end-to-end-release-evidence/sample-audit-chain-verification.json
	@python3 -c 'import json, pathlib; [json.loads(path.read_text()) for path in pathlib.Path("examples/end-to-end-release-evidence").glob("*.json")]'
	@grep -F '/v1/reports/release-readiness' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F '/v1/audit-chain/verify' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F '/v1/customer-packages' examples/end-to-end-release-evidence/run-local-demo.sh >/dev/null
	@grep -F 'not legal' examples/end-to-end-release-evidence/README.md >/dev/null

black-box-demo-check: ## Run live PostgreSQL black-box API/worker demo; requires EVYDENCE_TEST_DATABASE_URL
	@scripts/black_box_demo_check.sh

benchmark-check: ## Run the checked app-layer release evidence benchmark
	@$(GO) test ./internal/app -bench BenchmarkReleaseEvidenceIngestion -benchtime=100x -run '^$$' -benchmem
	@grep -F 'BenchmarkReleaseEvidenceIngestion' docs/reference/benchmark-results.md >/dev/null
	@grep -F 'API writer replicas: `1`' docs/reference/capacity-and-failures.md >/dev/null

package-viewer-check: ## Validate local package viewer and walkthrough
	@test -f site/package-viewer/index.html
	@test -f docs/how-to/view-packages.md
	@grep -F 'Load bundled demo' site/package-viewer/index.html >/dev/null
	@grep -F 'textContent' site/package-viewer/index.html >/dev/null
	@! grep -F 'innerHTML' site/package-viewer/index.html >/dev/null
	@grep -F 'examples/end-to-end-release-evidence/sample-customer-package-manifest.json' docs/how-to/view-packages.md >/dev/null

fast-check: ## Run non-mutating fast validation
	@$(MAKE) test
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
