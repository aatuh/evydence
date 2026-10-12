# Evydence implementation handoff

This how-to is for the developer and receiving Codex instance taking over on
another machine. Snapshot date: **2026-10-12**. Recheck live state on takeover;
this document is not a release-readiness or compliance claim.

## Get the files

The handoff is delivered on `agent/implementation-handoff-20261012`. Its
documentation changes may still be awaiting required CI and merge. To get them
before that merge:

```sh
git clone --branch agent/implementation-handoff-20261012 https://github.com/aatuh/evydence.git
cd evydence
git status --short --branch
git merge-base --is-ancestor 546de837479e7123870ccec0d8cb0811a00f312d HEAD
```

Expected: a clean checkout containing this file and `GOAL.txt`, and a successful
ancestry check. Once the handoff PR is merged, a normal clone of `master` also
contains these files. Fetch and compare current remote refs before choosing a
development branch; do not assume this snapshot is still the latest head.

## Start the receiving instance

Give the new instance this prompt from the repository directory:

```text
Read AGENTS.md, HANDOFF.md, GOAL.txt, .EVYDENCE_CODEX_BACKLOG.md, and
docs/reference/source-of-truth.md. Verify Git state, hosted CI evidence,
ticket dependencies, and implementation not yet reflected in the backlog.
Report any current blockers and recommend the next dependency-ready ticket.
Do not restart completed work or treat this snapshot as current external proof.
Use the goal objective in GOAL.txt when I activate the new thread's goal.
```

Read [README.md](README.md) for product boundaries. The [backlog](.EVYDENCE_CODEX_BACKLOG.md)
owns ticket state and completion evidence; [AGENTS.md](AGENTS.md) owns execution
policy. This document does not override either.

[GOAL.txt](GOAL.txt) is a verbatim export of the source thread's objective,
apart from its terminating newline. The source goal was **blocked**, not
complete, when exported. That lifecycle status is not proof of a present
technical blocker; the receiving instance must reassess the actual state.
Reading this file does not activate a goal. Set the receiving thread's goal
through its goal control using the text in `GOAL.txt` (or `/goal <objective>`
where supported). Goals are thread-scoped, not repository-global state; see
[official OpenAI Goals guidance](https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex).

Stop sending implementation work to the old instance after takeover. Do not
let two instances mutate the same ticket or branch without explicit ownership.

## Progress checkpoint and next work

- [PR #27](https://github.com/aatuh/evydence/pull/27) merged all 631 feature
  commits without squashing or rebasing. The retained feature branch is
  `agent/evy-403-completion` at `6abac9670e566375256dbb44a4126a6822409da4`.
- The implementation checkpoint on `master` is
  `546de837479e7123870ccec0d8cb0811a00f312d`. Local and remote `master`
  matched and the checkout was clean before preparing these handoff docs.
  The merge's tracked tree exactly matches the validated feature tree.
- EVY-903 through EVY-906 and EVY-1001 through EVY-1004 are marked complete.
  EVY-1006 and EVY-1101 through EVY-1103 are also marked complete. Consult
  each ticket's evidence rather than treating this subset as a full status list.
- **EVY-1005** is the recommended next P0 candidate: SSO sessions, cookies,
  bearer tokens, OIDC/SAML verification, and credential lifecycle. It remains
  `[ ]`, size XL. Its dependencies EVY-205, EVY-1002, and EVY-1004 are `[x]`.
  No EVY-1005 implementation or percentage estimate is claimed by this handoff.
  Inspect current services and tests before planning the missing work; initial
  target paths or validation package paths may predate the EVY-906 refactor.
  Map any retired paths to their current owners without dropping required checks.
- The goal's production Ledger-removal milestone is already satisfied by
  EVY-906. Preserve focused services and bounded database queries; do not
  reopen that completed ticket merely because the exported goal mentions it.
- Keep working one dependency-ready ticket at a time. Do not cut a stable
  release before EVY-170 permits it. External reviews, publication, pilots,
  and maintainer-owned evidence remain incomplete until real proof exists.

## Verified checks and integration repairs

On feature head `6abac9670e566375256dbb44a4126a6822409da4`:

- [Production Check run 38165154516](https://github.com/aatuh/evydence/actions/runs/38165154516)
  passed, including `make production-check` with live PostgreSQL and MinIO.
  Runtime tests, race, security, migrations, coverage, recovery, benchmarks,
  black-box flows, and release-artifact smoke checks were covered by that gate.
- [CodeQL Analyze run 38165154557](https://github.com/aatuh/evydence/actions/runs/38165154557)
  passed. Both required checks were verified before merge; neither was bypassed.

On merge commit `546de837479e7123870ccec0d8cb0811a00f312d`,
[CodeQL run 38205293633](https://github.com/aatuh/evydence/actions/runs/38205293633)
passed. [Production CI run 38205293589](https://github.com/aatuh/evydence/actions/runs/38205293589)
was still running when this snapshot was prepared; no final result is claimed.
Later documentation commits and their CI are separate evidence. Recheck:

```sh
gh run view 38205293589 --repo aatuh/evydence
gh run list --repo aatuh/evydence --branch master --limit 5
```

Integration fixes already committed; investigate a new failure before repeating
these repairs:

- `ee8723c3`: source-built, pinned disposable MinIO/client fixtures instead of
  unavailable upstream container tags.
- `1be6884a`: tracked byte-identical released OpenAPI baseline, no ignored cache
  dependency, with compatibility checking before expensive CI phases.
- `77115186`: exact prerelease compatibility review for 205 normalized changes;
  no baseline reset, blanket exception, or weaker checker.
- `30099da7`: snapshot-test transaction cleanup scoped to each case so small
  connection pools cannot deadlock; production pool behavior is unchanged.
- `6abac967`: hermetic synthetic Google credential fixtures and early API
  bootstrap tests; no ambient cloud credential dependency or signer fallback.

Only CodeQL alert **#29** was dismissed as a verified false positive with user
approval: API-key replay drops secret/hash and returns before public-manifest
SHA-256 hashing. See the [audit note](https://github.com/aatuh/evydence/pull/27#issuecomment-6111603357).
This is not evidence that all security findings are resolved. Required CodeQL
analysis remains enabled.

## Rebuild machine-local setup

Use the Go version in [go.mod](go.mod) (currently `1.26.9`), Git, GitHub CLI,
Make, Python 3, and Docker with Compose. Check [Makefile](Makefile) and the
[CI workflow](.github/workflows/ci.yml) for the actual pinned QA tooling;
`make help` lists gates and `make tools` installs the Go QA tools.

Follow [install and operate](docs/how-to/install-and-operate.md),
[configuration](docs/reference/configuration.md), and
[release validation](docs/reference/release-validation.md) for dependencies
and test configuration. Use disposable PostgreSQL and S3-compatible fixtures;
live gates need `EVYDENCE_TEST_DATABASE_URL` and the documented
`EVYDENCE_TEST_S3_*` configuration. Do not assume old container names, ports,
temporary tool wrappers, or cache locations exist on the receiving machine.
MinIO fixtures are isolated development/CI assets, not a production recommendation.

Install the custom skills required by `AGENTS.md`, with their referenced
resources, before implementation. These are not supplied by a Git clone.
For EVY-1005, start with `secure-code-change-loop` and the applicable
authentication, tenant-authorization, API-input, and secrets/privacy skills.

Authenticate Codex, GitHub, and any required providers separately. Do not copy
credentials into this document, Git, prompts, or commit messages. Do not copy
the whole Codex configuration directory indiscriminately. Recreate private
environment files securely; transfer actual databases, evidence objects, or
signing keys only under a separately scoped migration plan. Development
takeover does not require migrating production data.

## Working constraints

- Preserve test-first development, focused checks during iteration, and every
  required final gate before closing a ticket. Do not weaken tests for speed.
  Use [test strategy](docs/reference/test-strategy.md) and the active ticket
  for exact requirements. Avoid redundant unchanged full-suite runs.
- Preserve tenant isolation, append-only evidence, idempotency, canonical
  hashes, signature/digest verification, redaction, and the retired aggregate
  boundary. PostgreSQL remains required for API evaluation.
- Commit verified units with Conventional Commits and ticket IDs. Commit
  messages must contain no personal names or machine-specific paths. Do not
  rewrite history, force-push, or delete retained branches without approval.
- The verified solo-maintainer policy keeps `Production Check` and
  `CodeQL Analyze` required and up-to-date, without mandatory reviews,
  CODEOWNERS approvals, linear history, or conversation resolution. Administrator
  enforcement is disabled; that is a bypass capability, not permission to use
  it. Do not change protections or bypass checks as part of takeover. Recheck
  [maintainer review policy](docs/reference/maintainer-review-policy.md) and
  live settings before reporting current enforcement.

This transfer is documentation and development context only. It does not
deploy the application, publish a release, activate the receiving goal, or
prove provider availability or production suitability on the new machine.

## Handoff-only validation

`make docs-check`, `make backlog-check`, and `git diff --check` passed while
preparing these documentation changes. The exported objective was compared
with the source thread's saved goal and matched exactly apart from its final
newline. Ticket headings/checkmarks were preserved, and new files were checked
for machine-specific paths and credential assignments. Full runtime, race,
and live-dependency gates were not rerun locally for this documentation-only
change; the earlier exact-commit CI evidence above is not relabeled as validation
of a later commit or of the receiving machine.
