GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

TOOLS := golangci-lint gosec govulncheck
GOLANGCI_LINT_VERSION ?= v2.11.4
GOSEC_VERSION ?= v2.25.0
GOVULNCHECK_VERSION ?= v1.2.0

.PHONY: help tools fmt lint vuln gosec test test-race coverage openapi-check docs-check deploy-check sdk-check fast-check finalize compose-up compose-down migrate live-postgres-check postgres-integration-test clean

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

openapi.yaml: ## Generate committed OpenAPI source
	@$(GO) run ./cmd/openapi > openapi.yaml

openapi-check: openapi.yaml ## Validate OpenAPI generation and route contract tests
	@$(GO) test ./internal/adapters/httpapi -run 'TestRoutesValidateAndOpenAPIRenders'
	@$(GO) run ./cmd/openapi > /tmp/evydence-openapi.yaml
	@cmp -s openapi.yaml /tmp/evydence-openapi.yaml

docs-check: ## Validate canonical docs exist and avoid forbidden product claims
	@test -f README.md
	@test -f docs/architecture.md
	@test -f docs/api.md
	@test -f docs/operations.md
	@test -f docs/kubernetes.md
	@test -f docs/air-gapped.md
	@test -f docs/release-signing.md
	@test -f docs/production-hardening.md
	@! grep -R -i "automatically compliant\|certified secure\|legally sufficient\|SBOM is complete\|all vulnerabilities detected" README.md docs

deploy-check: ## Validate deployment and air-gap skeletons exist
	@test -f deploy/helm/evydence/Chart.yaml
	@test -f deploy/helm/evydence/values.yaml
	@test -f deploy/helm/evydence/templates/deployment-api.yaml
	@test -f deploy/helm/evydence/templates/deployment-worker.yaml
	@test -f deploy/airgap/manifest.yaml

sdk-check: ## Validate curated SDK example files exist
	@test -f sdk/go/evydence/client.go
	@test -f sdk/typescript/client.ts
	@test -f sdk/python/evydence_client.py

fast-check: ## Run non-mutating fast validation
	@$(MAKE) test
	@$(MAKE) openapi-check
	@$(MAKE) docs-check
	@$(MAKE) deploy-check
	@$(MAKE) sdk-check

finalize: ## Thorough validity check
	@$(MAKE) fmt
	@$(MAKE) test
	@$(MAKE) openapi-check
	@$(MAKE) docs-check
	@$(MAKE) deploy-check
	@$(MAKE) sdk-check

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
