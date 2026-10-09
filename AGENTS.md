# AGENTS.md

You are working on Evydence, a self-hosted API Evidence and Compliance Ledger.

Evydence is a self-hosted, API-first, tamper-evident evidence ledger for
software product teams. It captures, verifies, links, and reports release,
build, artifact, SBOM, VEX, vulnerability, OpenAPI, approval, exception,
deployment, incident, and control evidence.

The product supports compliance readiness and technical evidence organization. It must not claim to make customers legally compliant, certified secure, auditor-ready without review, or automatically compliant with CRA, SOC 2, ISO, or any other framework.

The current repository is a Go implementation, not a skeleton. As of the
current checkout it includes a Go module, `cmd/`, `internal/`, `docs/`,
`migrations/`, `deploy/`, `sdk/`, `site/`, `openapi.yaml`, Docker/Compose
files, GitHub Actions workflows, examples, release-candidate metadata, and
project-owned Makefile gates. Still verify the actual checkout before making or
reporting claims, because local and public state can drift.

---

## 0) First move

Before changing files, state the relevant assumptions for the task:

- Current repo state: confirm which files/directories exist rather than relying only on `.initial_design.md` or Makefile intent.
- Change type: documentation, tooling, feature, bug fix, API contract, persistence, security, deployment, or refactor.
- Security context: classify every non-documentation code change as `api`, `authz`, `session-auth`, `provider-webhook`, `cli`, `frontend`, `secrets-privacy`, `data`, `infra`, `library`, or `none`.
- Trust boundaries: name the user, tenant, collector, API, storage, signing-key, provider, file upload, and deployment boundaries affected by the change.
- Validation plan: name the narrow checks and final project-owned gate you intend to run.

If the context is `none`, state why. Documentation-only changes do not need the secure code change loop, but they still need source-of-truth checks.

## 0.1) Backlog execution contract

When `.EVYDENCE_CODEX_BACKLOG.md` is present, it is execution state, not a wishlist.

- Status syntax is strict: `[ ]` means incomplete; `[x]` means complete only after the ticket Definition of Done, required validation, compatibility work, and completion evidence are satisfied. Partial work stays `[ ]`.
- Work one backlog ticket at a time. Verify every listed dependency before implementation and do not skip a blocking correctness or security ticket to start easier later work.
- Use Conventional Commits and include the ticket ID, for example `fix(storage): enforce tenant-safe object identity (EVY-404)`. For nontrivial commits include `Why:`, `What:`, `Verification:`, `Compatibility:`, and `Ticket: EVY-XXX`.
- Run every validation command required by the active ticket plus the strongest applicable project-owned final gate. A skipped or unavailable required live dependency is a blocker, not a passing check.
- Update `.EVYDENCE_CODEX_BACKLOG.md` only after the implementation and required checks genuinely satisfy the ticket. Record exact commands/results and compatibility limits. Do not invent a commit's future SHA; use a follow-up tracking commit when necessary.
- Never fabricate repository settings, external review, provider verification, pilot evidence, release publication, benchmark output, or other external proof. External/maintainer-owned work remains incomplete until the required real evidence exists.
- Preserve unrelated work and Git history. Do not force-push, rewrite history, reset hard, clean untracked files, or destructively restore existing changes unless the user explicitly authorizes that action.

---

## 1) Agent implementation loop

For code changes:

1. Use `secure-code-change-loop` before implementation or refactoring.
2. Inspect the smallest affected module, interface, schema, command, and documentation surface.
3. Follow existing repo patterns before introducing new structure.
4. Write or update a failing test first unless the task is documentation-only or the user explicitly asks not to add tests.
5. Implement the smallest change that preserves the security and architecture invariants.
6. Update contracts, migrations, configuration examples, README, or docs when behavior changes require it.
7. Run targeted checks during iteration.
8. Run the strongest relevant project-owned gate before closing, unless the user explicitly limits validation.
9. Report changed files, checks run, skipped checks with reasons, and residual risk.

When refactoring auth, authorization, validation, provider integration, filesystem handling, logging, config, exports, or privacy-sensitive code, identify invariants first and add characterization tests if coverage is missing.

## 2) Repository source of truth

Use these sources in this order:

1. Actual committed files and directories in the checkout.
2. `README.md` for public product positioning, current status, evaluation path,
   and non-claims.
3. `docs/reference/source-of-truth.md` for canonical documentation ownership.
4. Package manifests, schemas, migrations, OpenAPI files, docs, CI, deployment
   files, examples, SDKs, and release metadata.
5. `Makefile` for declared project-owned commands.
6. User instructions in the current task.

Important caveat: documentation and release notes are not proof by themselves.
Treat architecture, endpoints, tables, deployment modes, and release-readiness
claims as implemented only when backed by code, schemas, migrations, tests,
generated OpenAPI, committed examples, release artifacts, or successfully run
project-owned checks.

Do not report checks as passing unless you run them successfully in the current
checkout or cite a verified public workflow/release artifact.

---

## 3) Tech stack and commands

Current detected project state:

- Go module: `github.com/aatuh/evydence`.
- Required API foundation: `github.com/aatuh/api-toolkit/v3`.
- Main process entry points live under `cmd/`.
- Core application/domain code lives under `internal/`.
- HTTP API contract is generated into committed `openapi.yaml`.
- Persistence uses migrations under `migrations/` and PostgreSQL-backed
  adapters under `internal/adapters/postgres`.
- Deployment examples include Docker/Compose, production-like Compose, Helm,
  and air-gapped manifests.
- Documentation lives under `docs/`; the marketing site lives under
  `site/marketing`.
- SDK wrappers live under `sdk/`.
- GitHub Actions workflows live under `.github/workflows`.

Required API toolkit:

- Future Go HTTP API implementation must use `github.com/aatuh/api-toolkit/v3` as the API foundation.
- Use the toolkit for stable ports, middleware, request/response helpers, Problem Details, route contracts, idempotency, security profile, system endpoints, tests, and OpenAPI-aligned API workflows where applicable.
- Use `github.com/aatuh/api-toolkit/contrib/v3` only for concrete adapters and integration wiring that belong outside core domain/application logic.
- Do not build a parallel local framework for concerns the toolkit already provides unless there is a documented project-specific reason.

Use `make help` to inspect the current target list. Important project-owned
targets include:

- `make help`
- `make tools`
- `make fmt`
- `make lint`
- `make vuln`
- `make gosec`
- `make test`
- `make test-race`
- `make coverage`
- `make openapi-check`
- `make openapi-precision-check`
- `make docs-check`
- `make deploy-check`
- `make sdk-check`
- `make demo-check`
- `make package-viewer-check`
- `make fast-check`
- `make finalize`
- `make release-acceptance`
- `make release-check`
- `make production-check`
- `make release-candidate-check TAG=vX.Y.Z-rc.N`
- `make public-release-verify TAG=vX.Y.Z-rc.N`
- `make compose-up`
- `make compose-down`
- `make migrate`
- `make live-postgres-check`
- `make postgres-integration-test`
- `make clean`

Prefer narrow package checks while iterating, then use `make fast-check` or
`make finalize` as the final local gate for ordinary source/doc changes.
`make production-check` and `make release-check-local-postgres` require live
PostgreSQL configuration. `make release-candidate-check` requires release
candidate signing/release material.

Do not invent commands. If a needed security, docs, API, migration, or release check is missing, say what should be added.

---

## 4) Architecture rules

The intended product architecture is an API-first, self-hosted evidence ledger. Preserve these boundaries as code is introduced:

- Core/domain logic must stay independent of HTTP routers, SQL drivers, object storage SDKs, queues, KMS providers, GitHub/GitLab clients, scanner formats, and UI frameworks.
- Use ports-and-adapters boundaries. Put process bootstrapping under `cmd/*`, internal service/application code under `internal/*`, and public reusable client/verifier packages under `pkg/*` only when there is a real public API reason.
- HTTP/API code must use the required `aatuh/api-toolkit` primitives where applicable instead of local one-off middleware and response helpers.
- PostgreSQL is the intended source of truth; object storage is for raw payloads and large exports; queue/worker code handles parsing, signing, verification, and report generation.
- Do not introduce a graph database before PostgreSQL adjacency tables are proven insufficient.
- Store immutable evidence, audit entries, signatures, chain checkpoints, and release bundle manifests as append-only records. Amend by superseding, linking, or appending new records.
- Every tenant-scoped resource must carry explicit tenant ownership and enforce tenant isolation at the application and persistence boundaries.
- Version schemas, report templates, policy definitions, parsers, evidence formats, and bundle manifests.
- Use structured APIs/parsers for JSON, OpenAPI, SBOM, VEX, archives, signatures, and problem details. Avoid ad hoc string parsing for security-sensitive inputs.

Do not silently import architecture, commands, paths, or assumptions from another project. Verify them against the current Evydence checkout before use.

---

## 5) Domain risk profile

This project handles high-trust security and compliance evidence. Treat the following as security-sensitive:

- tenant isolation, organizations, products, projects, releases, environments, and customer package scopes;
- collector identities, API keys, OAuth/OIDC subjects, mTLS identities, webhook signatures, and service tokens;
- artifact digests, canonical hashes, signatures, chain entries, checkpoints, signing keys, KMS/HSM integration, and verification results;
- SBOMs, VEX documents, vulnerability scans, vulnerability decisions, exceptions, waivers, approvals, and incident timelines;
- raw evidence payloads, object storage paths, exports, reports, logs, metrics, traces, and customer-facing packages.

Required invariants:

- Evidence core fields are immutable after creation.
- Links, approvals, exceptions, timeline events, audit entries, and chain entries are append-only.
- Idempotent create operations must return the original result for the same key and reject reused keys with different request content.
- Hashes are computed over canonical, documented inputs.
- Uploaded payload bytes must match declared digests before trust is assigned.
- Tenant checks happen before reads, writes, links, exports, verification results, and report generation.
- Collector tokens are least-privilege, scoped, revocable, audited, and write-only by default where possible.
- Signing keys and verification trust roots have rotation, revocation, audit, and least-privilege controls.
- Customer packages must use explicit redaction profiles and scoped access.

Use these focused skills when relevant:

- `api-input-validation-bug-loop` for HTTP/API/schema/input handling.
- `authz-tenant-isolation-loop` for ownership, tenant, account, project, product, role, or scoped-resource behavior.
- `session-auth-security-loop` for login, OAuth/OIDC, cookies, bearer tokens, sessions, logout, or CSRF.
- `provider-webhook-security-loop` for signed callbacks, provider APIs, CI/OIDC integrations, external adapters, and idempotency.
- `cli-input-security-loop` for CLI args, env vars, paths, files, subprocesses, archives, and destructive flags.
- `frontend-security-loop` for browser UI, redirects, XSS, CSP, token exposure, analytics, consent, and client storage.
- `secrets-logging-privacy-loop` for secrets, logs, errors, PII, telemetry, exports, env files, and privacy-facing behavior.

---

## 6) Testing and validation rules

Use the strongest project-owned checks that exist and are relevant. Prefer Makefile targets over ad hoc command sets.

Current useful command discovery:

- `make help` lists declared targets.

When a Go module and source tree exist:

- Run targeted `go test ./path/...` during iteration.
- Run `make test` for unit tests.
- Run `make test-race` for concurrency-sensitive changes.
- Run `make coverage` when coverage evidence matters.
- Run `make lint`, `make gosec`, and `make vuln` for implementation changes with security impact.
- Run `make fast-check` for non-mutating broad validation when the referenced files exist.
- Run `make finalize` before closing broad implementation work.

When API contracts exist:

- Update the OpenAPI source for route, schema, status code, auth, header, idempotency, and error changes.
- Validate route behavior and OpenAPI alignment with project-owned tests or `make openapi-check` once available.
- Use RFC 9457-style Problem Details consistently.

When persistence exists:

- Add migrations for schema changes.
- Test repository/store behavior, transaction boundaries, tenant filters, uniqueness/idempotency constraints, and rollback/upgrade behavior.
- Run live Postgres/Redis checks only when the required services and environment variables are configured.

When documentation changes:

- Keep source-of-truth docs accurate and avoid duplicating command lists or behavior claims.
- Use `make docs-check` once the referenced docs, API, SDK, and deployment files exist.
- Until then, use targeted source inspection and report that full docs checks are not yet runnable in the skeleton repo.

Never claim validation was run unless it was actually run.

---

## 7) Change quality bar

A change is not complete until it preserves the relevant product invariants:

- API behavior is explicit about auth, idempotency, validation, error shape, status codes, pagination/filtering, and immutability.
- Data behavior is explicit about tenant scope, append-only records, canonical hashes, digest verification, signatures, and replay/reproducibility.
- Security behavior is explicit about trust boundaries, least privilege, auditability, secrets handling, and redaction.
- Operational behavior is explicit about logs, metrics, traces, health/readiness, migrations, backups, and failure modes.
- Documentation states what the product supports, what it does not prove, and what remains an assumption or limitation.

Avoid broad abstractions until repeated real use makes them necessary. Prefer boring, testable, deterministic code over clever policy, signing, parsing, or report generation paths.

---

## 8) Pre-audit self check

Before finalizing substantial work, verify:

- Core logic is not coupled to adapters or framework details.
- API inputs, path/query values, files, archives, JSON, and provider payloads are validated through structured parsers.
- Authorization is enforced server-side and is not delegated to frontend route guards.
- Tenant filters cannot be bypassed by IDs, links, exports, reports, or verification endpoints.
- Idempotency, duplicate detection, and immutable/superseded record behavior have tests.
- Hashing, signing, canonicalization, and verification tests include negative cases.
- Error messages, logs, metrics, traces, reports, and exports do not leak secrets or unintended sensitive evidence.
- Public/customer-facing claims avoid compliance magic, legal sufficiency, scanner authority, or SBOM completeness claims.
- Docs, examples, OpenAPI, migrations, config, and deployment assets changed together when behavior changed.

---

## 9) Common audit failure avoidance

Do not:

- claim compliance, certification, legal sufficiency, complete SBOMs, complete vulnerability detection, or secure releases;
- allow silent edits to historical evidence;
- mutate release bundles, approval records, vulnerability decisions, audit records, or chain entries in place;
- trust webhook/provider/CI payloads before signature, token, OIDC, or source identity verification;
- store raw secrets, bearer tokens, webhook secrets, private keys, or unredacted sensitive payloads in logs or reports;
- expose detailed health, metrics, pprof, dependency status, or operator diagnostics without admin/internal access control;
- process archives, executable payloads, or uploaded files without size limits, type allowlists, digest checks, and sandbox/quarantine decisions;
- build customer packages without explicit scope, redaction profile, access audit, and previewable contents;
- treat `.initial_design.md` examples as already-implemented endpoint, schema, or table contracts;
- treat frontend visibility as authorization.

---

## 10) Documentation quality bar

Classify each doc as tutorial, how-to, reference, or explanation. Keep one primary audience and task per document.

Documentation must:

- use exact paths, commands, environment variable names, expected outcomes, and validation notes;
- state limitations, assumptions, non-goals, and evidence gaps plainly;
- keep command/setup references in one canonical place when possible;
- update canonical docs before adding secondary summaries;
- remove or merge duplicative prose that would drift;
- mark unimplemented design as intent, roadmap, or proposed behavior;
- avoid saying behavior is verified unless checked against code, config, schema, tests, or commands.

Product language should prefer:

- "supports compliance readiness";
- "organizes and verifies technical evidence";
- "makes release evidence reproducible and auditable";
- "provides tamper-evident records";
- "shows gaps, assumptions, exceptions, and limitations".

Product language must not say:

- "automatically compliant";
- "certified secure";
- "legally sufficient";
- "regulator-ready without review";
- "all vulnerabilities detected";
- "SBOM is complete";
- "scanner findings are authoritative".

---

## 11) Output format

For implementation work, final responses should include:

1. What changed and why.
2. Files changed.
3. Commands run and results.
4. Security context, trust boundaries, and invariants covered.
5. Tests or checks skipped, with reasons.
6. Residual risks or follow-up work.

For documentation-only work, include:

1. What changed and which source-of-truth evidence was used.
2. Files changed.
3. Checks run or why full checks were not applicable.
4. Claims intentionally avoided because repo evidence did not prove them.
