# Documentation Source Of Truth

Use this map to avoid duplicating long command lists, release criteria, or
product-boundary language across the docs.

| Topic | Canonical Source | Notes |
| --- | --- | --- |
| Product positioning and current status | `README.md` and `docs/reference/production-readiness.md` | Other docs should link here instead of redefining release status. |
| Buyer evaluation path | `docs/buyer-overview.md` | Links demo, package viewer, release evidence, capability map, and API review without duplicating commands. |
| Operator path | `docs/operator-overview.md` and `docs/operations.md` | Links install, config, deployment, gates, runbooks, and production boundaries. |
| Runtime configuration | `docs/reference/configuration.md` | How-to guides may show a short example, then link here for variables. |
| API routes, scopes, idempotency, schemas | `openapi.yaml`, `docs/api.md`, `docs/reference/api-inventory.md`, `docs/reference/api-contract-matrix.md`, and `docs/openapi/index.html` | `openapi.yaml` is generated; the inventory, matrix, and rendered OpenAPI docs are generated from it. |
| API versioning, deprecation, and compatibility exceptions | `docs/reference/api-versioning.md`, `docs/reference/openapi-baseline.json`, and `.github/openapi-breaking-exceptions.json` | The baseline is a release artifact; the checked exception file is exact and does not replace release review. |
| Product boundary and API stability | `docs/reference/product-boundary.md` and `openapi.yaml` | Stability is generated per operation as `x-evydence-stability`; the inventory, matrix, and route catalog must match it. |
| Verification result taxonomy and assurance profiles | `docs/reference/verification-results.md` | Defines machine states, `passed` requirements, profile fields, legacy migration behavior, and customer-package representation. |
| Local startup | `docs/tutorials/getting-started.md` | Uses in-process state only. |
| Durable operation | `docs/how-to/install-and-operate.md` | Includes PostgreSQL/object storage and production-like Compose rehearsal. |
| Kubernetes | `docs/kubernetes.md` | Helm-specific operator interface. |
| Hardened self-hosted topology | `docs/reference/hardened-reference-deployment.md` | One API writer, scalable workers, external PostgreSQL/object storage, TLS, secrets, backups, monitoring, signing, and operator-owned evidence. |
| HA and concurrency decision | `docs/reference/ha-strategy.md` | Current single-writer appliance decision, recovery boundaries, and multi-writer prerequisites. |
| Persistence decomposition inventory | `docs/reference/persistence-decomposition.md` | Generated map of focused mutation paths, remaining broad relational-state call sites, next split order, and regression checks. |
| Bounded-context ownership and package retirement | `docs/adr/0003-bounded-contexts.md` | Current owner map, allowed dependencies/events, transition paths, and the retirement sequence for `internal/domain` and `internal/app.Ledger`. |
| Release validation | `docs/reference/release-validation.md` | Canonical release gate behavior. |
| Test strategy and critical behavior evidence | `docs/reference/test-strategy.md` | Coverage floors, behavior-to-test matrix, deterministic fixture policy, and exact-commit CI evidence provenance. |
| Release-candidate evidence | `docs/reference/release-candidate.md` | Canonical release-candidate artifact checklist. |
| Release evidence artifact map | `docs/reference/release-evidence-index.md` | Maps each release artifact to generation and verification commands. |
| Production profiles and exit criteria | `docs/reference/production-readiness.md`, `docs/reference/production-exit-review.md`, and `docs/reference/stable-v0.1.0-exit-criteria.md` | Do not broaden status elsewhere without updating these. |
| Design-partner pilot checklist | `docs/how-to/pilot-deployment-checklist.md` | Narrow copy-paste checklist for one controlled self-hosted pilot profile. |
| Maintainer review ownership | `CODEOWNERS` and `docs/reference/maintainer-review-policy.md` | Branch protection or repository rules must enforce this before it is a merge gate. |
| Roadmap and cadence | `docs/reference/roadmap.md` | Public roadmap, supported release line, and cadence expectations. |
| Agent execution policy | `AGENTS.md` | Canonical repository-local execution contract for agents, including backlog status, commit, validation, evidence, and safety rules. |
| 9/10 implementation tracking | `docs/reference/world-class-backlog.md` and `.EVYDENCE_CODEX_BACKLOG.md` | The reference page explains tracking; the root backlog holds ticket state. Neither is a production claim or evidence of external completion. |
| Backlog issue labels | `docs/reference/issue-labels.md` | Use these labels and the backlog ticket template when creating maintainable issue records. |
| 9/10 evidence scorecard | `docs/reference/quality-scorecard.md` | Current repository and external evidence are deliberately separate. Do not raise the score from prose or local checks alone. |
| Backup/restore | `docs/runbooks/backup-restore.md` and `docs/runbooks/object-store-recovery.md` | Operator rehearsal steps, object-store recovery, and evidence to keep. |
| Evidence-format compatibility | `docs/reference/evidence-format-compatibility.md` | Tested input shapes, parser identities, resource bounds, unsupported encodings, and compatibility limits. |
| Upgrade | `docs/runbooks/upgrade.md` and `docs/reference/upgrade-compatibility-policy.md` | Migration, release artifact verification, supported paths, and API compatibility. |
| Incident response | `docs/runbooks/incident-response.md` | Secrets, tenant, object-store, signing, provider, and package boundaries. |
| Key rotation | `docs/runbooks/key-rotation.md` | Credential and signing-provider rotation boundaries. |
| Capacity and failure modes | `docs/reference/capacity-and-failures.md` and `docs/reference/benchmark-results.md` | Benchmark results are narrow and local. |
| Security reporting | `SECURITY.md` | Repository settings for private reporting must be verified on GitHub. |
| Threat model and security requirements | `docs/security/threat-model.md` and `docs/security/security-requirements.md` | Current trust boundaries, public-claim requirements, repository evidence, open security backlog, and explicitly external controls. |
| Support expectations | `SUPPORT.md` | Public support boundaries and sanitized-report rules. |
| Commercial pilot positioning | `docs/commercial/design-partner-pilot.md` and `COMMERCIAL.md` | Pilot docs must not imply legal compliance, certification, scanner authority, SBOM completeness, or secure releases. |
| Reusable product copy | `docs/commercial/product-landing-copy.md` | Website, outreach, and README excerpts should start from this conservative copy. |
| Category comparison | `docs/commercial/category-comparison.md` | Keep comparisons fair, non-hostile, and focused on category boundaries. |

## Repetition Policy

Repeat non-claims briefly where a document can be read alone, but keep detailed
wording in the canonical source. Prefer links over copying full checklists.

Allowed short boundary wording:

> Evydence supports compliance readiness and technical evidence organization;
> it does not make legal compliance conclusions, grant certification, prove SBOM
> completeness, treat scanner output as authoritative, or guarantee release
> security.

Do not create new variants of release status, production profiles, or supported
deployment modes outside the canonical sources above.
