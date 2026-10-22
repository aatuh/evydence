# Documentation Source Of Truth

Use this map to avoid duplicating long command lists, release criteria, or
product-boundary language across the docs.

| Topic | Canonical Source | Notes |
| --- | --- | --- |
| Product positioning and current status | `README.md` and `docs/reference/production-readiness.md` | Other docs should link here instead of redefining release status. |
| Buyer evaluation path | `docs/buyer-overview.md` | Links demo, package viewer, release evidence, capability map, and API review without duplicating commands. |
| Operator path | `docs/operator-overview.md` and `docs/operations.md` | Links install, config, deployment, gates, runbooks, and production boundaries. |
| Runtime configuration | `internal/platform/config/` and `docs/reference/configuration.md` | Schema metadata owns variable defaults and constraints. `make config-generate` updates the marked sections of the production example, canonical reference and Helm guide; `make config-check` detects drift. How-to guides link to the reference for variables. |
| Runtime observability | `docs/reference/observability.md` | Owns process diagnostics, metric families, scrape authority, cardinality and lifecycle-probe semantics. |
| API routes, scopes, idempotency, schemas | `openapi.yaml`, `docs/api.md`, `docs/reference/api-inventory.md`, `docs/reference/api-contract-matrix.md`, and `docs/openapi/index.html` | `openapi.yaml` is generated; the inventory, matrix, and rendered OpenAPI docs are generated from it. |
| API versioning, deprecation, and compatibility exceptions | `docs/reference/api-versioning.md`, `docs/reference/openapi-baseline.json`, and `.github/openapi-breaking-exceptions.json` | The baseline is a release artifact; the checked exception file is exact and does not replace release review. |
| Product boundary and API stability | `docs/reference/product-boundary.md` and `openapi.yaml` | Stability is generated per operation as `x-evydence-stability`; the inventory, matrix, and route catalog must match it. |
| Verification result taxonomy and assurance profiles | `docs/reference/verification-results.md` | Defines machine states, `passed` requirements, profile fields, legacy migration behavior, and customer-package representation. |
| Local startup | `docs/tutorials/getting-started.md` | Requires PostgreSQL, including local evaluation. |
| Durable operation | `docs/how-to/install-and-operate.md` | Includes PostgreSQL/object storage and production-like Compose rehearsal. |
| Kubernetes | `docs/kubernetes.md` | Helm-specific operator interface. |
| Hardened self-hosted topology | `docs/reference/hardened-reference-deployment.md` | One API writer, scalable workers, external PostgreSQL/object storage, TLS, secrets, backups, monitoring, signing, and operator-owned evidence. |
| HA and concurrency decision | `docs/reference/ha-strategy.md` | Current single-writer appliance decision, recovery boundaries, and multi-writer prerequisites. |
| Persistence decomposition inventory | `docs/reference/persistence-decomposition.md` | Generated map of focused mutation paths, remaining broad relational-state call sites, next split order, and regression checks. |
| Bounded-context ownership and package retirement | `docs/adr/0003-bounded-contexts.md` | Current owner map, allowed dependencies/events, transition paths, and the retirement sequence for `internal/domain` and `internal/app.Ledger`. |
| Go, QA tool and platform selections | `release/support-matrix.json` and `docs/reference/toolchain-platform-support.md` | `make support-matrix-check` checks build/CI selections and generated reference rows; ticket evidence owns actual qualification. |
| Dependency inventory and admission | `scripts/dependency_policy.py`, `scripts/dependency_comparison.py`, `scripts/dependency_inventory.py`, `scripts/dependency_node_sources.py`, `scripts/dependency_python_sources.py`, `scripts/dependency_build_tools.py`, `scripts/dependency_actions.py`, `scripts/dependency_go_tools.py`, `scripts/dependency_images.py`, `scripts/dependency_image_registry.py`, `release/tools/standalone-go.json`, `docs/reference/dependency-inventory.json`, `docs/reference/dependency-image-inventory.json` and `docs/reference/dependency-policy.md` | Offline admission semantics and source-bound dependency/tool/fixture/Action observations, with separate declared-image package observations; operator deployment choices, combined admission and live review integration remain incomplete under EVY-1407. |
| Dependency update review | `.github/dependabot.yml`, `scripts/test_dependency_updates.py` and `docs/reference/dependency-policy.md` | Local scope coverage and separate minor/patch and security groups; hosted activation and manual update limits remain explicit. |
| Dependency maintenance review | `scripts/dependency_maintenance.py`, `scripts/dependency_maintenance_sources.py`, `scripts/dependency_reports.py`, `docs/reference/dependency-maintenance.json` and `docs/reference/dependency-maintenance.md` | Source-bound version-age, repository activity/status and deprecation observations; unknown metadata remains explicit and signals do not certify maintenance health or admit dependencies. |
| PR source and dependency-provider observations | `scripts/dependency_review_provider.py`, `scripts/dependency_comparison.py` and `docs/reference/dependency-review-provider.md` | Authenticated PR/commit/tree/file correspondence and normalized provider rows; complete dependency coverage, trusted policy and hosted enforcement remain pending. |
| Immutable dependency inputs | `scripts/dependency_git_objects.py`, `scripts/dependency_inputs.py` and `docs/reference/dependency-inputs.md` | Git-verified source bytes, declared input families and explicit catalog gaps; no PR code execution or complete dependency admission verdict. |
| Trusted dependency classifier build | `scripts/dependency_classifier.py` and `docs/reference/dependency-classifier.md` | Explicit base Git sources/locks, private credential-free build and executable identity checks; base authorization and complete admission remain separate. |
| Trusted Git dependency collection | `scripts/dependency_collection.py`, `scripts/dependency_inventory.py` and `docs/reference/dependency-collection.md` | Private Git data exports, distinct trusted generator/proposed input hashes, base-built classification and final PR consistency checks; complete scope/advisory joins and hosted admission remain pending. |
| Source package admission decisions | `release/dependency-policy.json`, `scripts/dependency_admission.py`, `scripts/dependency_advisories.py` and `docs/reference/dependency-admission.md` | Current-target Git policy, exact package/origin/source changes and bounded advisory observations; a partial decision with full coverage and real exception review still pending. |
| Fixture source and notice records | `testdata/fixture-provenance.v1.json`, `scripts/fixture_provenance.py`, `testdata/licenses/` and `docs/reference/fixture-provenance.md` | Fixture coverage, immutable bytes, pinned source transformations and recorded declarations with separate text classifications; live admission remains incomplete under EVY-1407. |
| Release validation | `docs/reference/release-validation.md` | Canonical release gate behavior. |
| Changelog, source fragments and generated release notes | `changes/policy.json`, `changes/fragments/`, `scripts/release_notes.py`, and `docs/reference/release-history.md` | Pins preserved manual history, checks material delivery coverage and compatibility inventories, and requires matching committed candidate notes before packaging or local tagging. |
| Reproducible release payloads | `docs/reference/reproducible-builds.md` and `scripts/release_build.py` | Shared unsigned build recipe, source-derived identity time, normalized archives, actual-byte comparison and independent-runner evidence boundaries. |
| Release SBOM and provenance profile | `docs/reference/release-supply-chain.md` and `scripts/release_evidence_profile.py` | Exact binary/archive subjects, public package-coordinate profile, provenance inputs and evidence index; integration and qualification status are explicit. |
| Test strategy and critical behavior evidence | `docs/reference/test-strategy.md` | Coverage floors, behavior-to-test matrix, deterministic fixture policy, and exact-commit CI evidence provenance. |
| Release-candidate evidence | `docs/reference/release-candidate.md` | Canonical release-candidate artifact checklist. |
| Release evidence artifact map | `docs/reference/release-evidence-index.md` | Maps each release artifact to generation and verification commands. |
| Release publisher identity and custody | `docs/release-signing.md` and `release/signing-policy.json` | Exact issuer/workflow/ref/source policy, protected environment, legacy pins, credential custody, revocation and rollout evidence limits. |
| Security support windows and withdrawn releases | `release/lifecycle-policy.json`, `release/current.json`, and `docs/reference/release-support.md` | Machine-readable current-release selection and event-based support; the generated reference preserves withdrawal warnings. `docs/reference/release-revocation.md` owns the maintainer procedure. |
| Private security intake and response | `SECURITY.md` and `docs/reference/security-response.md` | Reporter entry point, sole response owner, best-effort availability, triage, disclosure and emergency response; support windows remain in the lifecycle policy. |
| Production profiles and exit criteria | `docs/reference/production-readiness.md`, `docs/reference/production-exit-review.md`, and `docs/reference/stable-v0.1.0-exit-criteria.md` | Do not broaden status elsewhere without updating these. |
| Design-partner pilot checklist | `docs/how-to/pilot-deployment-checklist.md` | Narrow copy-paste checklist for one controlled self-hosted pilot profile. |
| Maintainer review ownership | `CODEOWNERS` and `docs/reference/maintainer-review-policy.md` | CODEOWNERS is an ownership reference; the policy owns high-risk self-review expectations and links to provider verification. |
| Maintainer ownership and recovery | `GOVERNANCE.md` and `docs/reference/continuity-plan.md` | Owns solo-maintainer release/security duties, asset recovery checklist and availability limits; a second maintainer is optional. |
| GitHub repository protection | `docs/reference/repository-controls.md` and `scripts/verify_github_controls.sh` | Canonical provider profile, dated observations, refresh cadence, and fail-closed live verification. |
| Roadmap and cadence | `docs/reference/roadmap.md` | Public roadmap, supported release line, and cadence expectations. |
| Agent execution policy | `AGENTS.md` | Canonical repository-local execution contract for agents, including backlog status, commit, validation, evidence, and safety rules. |
| Implementation takeover | `HANDOFF.md` and `GOAL.txt` | Dated handoff snapshot and exported goal objective; ticket state stays in the root backlog, and the user activates the goal in the receiving thread. |
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
