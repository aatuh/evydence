#!/usr/bin/env python3
"""Generate and validate the critical behavior test-evidence matrix."""

from __future__ import annotations

import argparse
import difflib
import pathlib
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "reference" / "test-strategy.md"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_BEHAVIOR_IDS = {
    "tenant-isolation",
    "authorization",
    "atomicity",
    "idempotency",
    "audit-integrity",
    "object-pairing",
    "parser-conformance",
    "verification",
    "redaction",
    "packages",
    "backup-restore",
    "upgrade",
}


@dataclass(frozen=True)
class Evidence:
    references: tuple[str, ...] = ()
    gap: str = ""

    def render(self) -> str:
        if self.references:
            return "<br>".join(f"`{reference}`" for reference in self.references)
        return f"N/A: {self.gap}"


@dataclass(frozen=True)
class Behavior:
    identifier: str
    behavior: str
    invariant: str
    positive: Evidence
    negative: Evidence
    failure: Evidence
    unit: Evidence
    integration: Evidence
    black_box: Evidence
    race: Evidence
    fuzz: Evidence


def refs(*values: str) -> Evidence:
    return Evidence(references=tuple(values))


def gap(reason: str) -> Evidence:
    return Evidence(gap=reason)


RACE_GATE = refs("Makefile::test-race:")

BEHAVIORS = (
    Behavior(
        "tenant-isolation",
        "Tenant isolation",
        "A resource owned by one tenant is never readable, writable, linkable, exportable, or processed as another tenant.",
        refs("internal/app/ledger_test.go::TestTenantScopedEvidenceAndAPIKeyAuth"),
        refs("internal/adapters/httpapi/router_test.go::TestCrossTenantEvidenceReadDenied"),
        refs("cmd/evydence-worker/main_test.go::TestProcessJobFailsClosedForStateLoadAndTenantMismatches"),
        refs("internal/app/ledger_test.go::TestTenantScopedEvidenceAndAPIKeyAuth"),
        refs("internal/adapters/httpapi/router_test.go::TestCrossTenantEvidenceReadDenied"),
        refs("scripts/black_box_demo_check.sh"),
        RACE_GATE,
        gap("tenant/resource combinations are exhaustively table-tested; unstructured parser fuzzing does not exercise authorization policy"),
    ),
    Behavior(
        "authorization",
        "Authorization and scope coverage",
        "Every protected command and route enforces its server-side scope and resource policy; frontend visibility never grants access.",
        refs("internal/app/authz_inventory_test.go::TestResourceScopedAuthorizationCoverageInventory"),
        refs("internal/app/ledger_test.go::TestScopedAPIKeyCannotWriteEvidence"),
        refs("internal/adapters/httpapi/router_test.go::TestInstanceAdminHTTPRequiresExplicitScope"),
        refs("internal/app/authz_inventory_test.go::TestResourceScopedAuthorizationCoverageInventory"),
        refs("internal/adapters/httpapi/router_test.go::TestInstanceAdminHTTPRequiresExplicitScope"),
        refs("scripts/black_box_demo_check.sh"),
        RACE_GATE,
        gap("scope and route inventories are finite structured sets and are checked exhaustively"),
    ),
    Behavior(
        "atomicity",
        "Transactional atomicity",
        "Domain rows, audit entries, outbox jobs, object metadata, and process-visible state commit together or remain invisible.",
        refs("internal/app/release_evidence_uow_test.go::TestReleaseEvidenceWritesUseUnitOfWorkAndPublishCacheAfterCommit"),
        refs("internal/app/release_evidence_uow_test.go::TestReleaseEvidenceWriteDoesNotPublishBeforeUnitOfWorkCommit"),
        refs("internal/adapters/postgres/failure_atomicity_test.go::TestPostgresFailureAtomicityRollsBackEveryPreCommitPhase"),
        refs("internal/app/release_evidence_uow_test.go::TestReleaseEvidenceRepositoryFailuresRollbackEveryReleaseEvidenceFamily"),
        refs("scripts/fault_injection_check.sh"),
        refs("scripts/black_box_demo_check.sh"),
        RACE_GATE,
        gap("transaction phases are deterministic injected states; arbitrary byte fuzzing is not an applicable state-space model"),
    ),
    Behavior(
        "idempotency",
        "Idempotency and replay",
        "The same actor/key/body returns one committed result; a changed body conflicts; failed or expired reservations recover without duplicate effects.",
        refs("internal/app/idempotency_test.go::TestWithIdempotencyCommitsCommandAndReplayTogether"),
        refs("internal/app/ledger_test.go::TestIdempotencyReplayAndConflict"),
        refs("internal/app/idempotency_test.go::TestWithIdempotencyRollsBackCommandWhenItFails"),
        refs("internal/app/idempotency_test.go::TestWithIdempotencyCommitsCommandAndReplayTogether"),
        refs("internal/adapters/postgres/idempotency_concurrency_test.go::TestStoreConcurrentIdempotencyAcrossLedgerInstances"),
        refs("scripts/black_box_demo_check.sh"),
        refs("internal/app/idempotency_concurrency_test.go::TestWithIdempotencyConcurrentReleaseBundleCommitsOneEffectAndReplay"),
        gap("request-body equivalence uses canonical hashes and explicit conflict vectors; parser fuzzing is tracked separately"),
    ),
    Behavior(
        "audit-integrity",
        "Audit-chain integrity",
        "Append-only audit sequences, canonical hashes, signatures, and checkpoints detect mutation, truncation, and invalid references.",
        refs("internal/app/ledger_test.go::TestEvidenceCanonicalHashAndAuditChainVerification"),
        refs("internal/app/ledger_test.go::TestAuditChainVerificationRecomputesStoredEntryFields"),
        refs("internal/app/ledger_test.go::TestAuditChainCheckpointVerificationDetectsTruncation"),
        refs("internal/app/ledger_test.go::TestAuditChainCanonicalV2CoversAllStoredEntryFields"),
        refs("internal/adapters/postgres/store_test.go::TestPostgresBackupRestoreRehearsalPreservesLedgerAndObjects"),
        refs("scripts/black_box_demo_check.sh"),
        RACE_GATE,
        gap("canonical-entry mutations and truncation are structured negative vectors, not free-form parser inputs"),
    ),
    Behavior(
        "object-pairing",
        "Database/object pairing",
        "Tenant, digest, size, media type, staging lifecycle, and final object bytes remain bound; missing or mismatched objects fail closed.",
        refs("internal/app/object_identity_test.go::TestVerifyObjectPayloadReadChecksBytesTenantSizeDigestAndMediaType"),
        refs("internal/app/object_identity_test.go::TestObjectIdentityRejectsAmbiguousTenantKeyAndDigestForms"),
        refs("internal/app/object_ingestion_test.go::TestUploadSBOMLeavesDiscoverableStagingObjectWhenTransactionFails"),
        refs("internal/app/object_ingestion_test.go::TestFinalizeStagedObjectPayloadRetriesSafelyAndGatesReaders"),
        refs("internal/adapters/objectstore/s3/live_integration_test.go::TestMinIOIntegrationStagesFinalizesMultipartAndChecksObjectLock"),
        refs("scripts/black_box_demo_check.sh"),
        refs("internal/adapters/postgres/object_reconciliation_concurrency_test.go::TestApplyObjectReconciliationRejectsStaleLifecycleSnapshot"),
        refs("internal/app/fuzz_test.go::FuzzValidDigest"),
    ),
    Behavior(
        "parser-conformance",
        "Parser conformance and bounds",
        "Supported SBOM, VEX, scanner, and OpenAPI inputs match pinned schemas/corpora and malformed or resource-heavy inputs fail closed.",
        refs("internal/app/parser_corpus_test.go::TestParserConformanceCorpus"),
        refs("internal/app/ledger_test.go::TestParsersRejectMalformedInputs"),
        refs("internal/app/parsers/cyclonedx/depth_preflight_test.go::TestParseBoundedReaderRejectsExcessiveDepthBeforeConsumingTail"),
        refs("internal/app/parsers/cyclonedx/parser_test.go::TestOfficialCycloneDX16FixturesAreAccepted"),
        refs("cmd/evydence-worker/main_test.go::TestProcessJobWithObjectsFailsSafelyForParserMismatches"),
        refs("scripts/black_box_demo_check.sh"),
        RACE_GATE,
        refs(
            "internal/app/parsers/cyclonedx/parser_test.go::FuzzCycloneDX",
            "internal/app/parsers/scanners/parser_test.go::FuzzParseBounded",
        ),
    ),
    Behavior(
        "verification",
        "Cryptographic verification",
        "Verification binds subject digests, signatures, identities, trust roots, time, and policy; unsupported or invalid material never becomes trusted.",
        refs("internal/adapters/verification/dsse/verifier_test.go::TestVerifyAttestationEnforcesPAEAndTrustedPolicy"),
        refs("internal/adapters/verification/sigstore/verifier_test.go::TestVerifyOfficialKeylessBundleFailsClosed"),
        refs("internal/app/verification_uow_test.go::TestSubjectVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit"),
        refs("internal/adapters/verification/dsse/verifier_test.go::TestVerifyAttestationEnforcesPAEAndTrustedPolicy"),
        refs("internal/adapters/verification/sigstore/verifier_test.go::TestVerifyOfficialKeylessBundle"),
        refs("scripts/black_box_release_artifact_check.sh"),
        RACE_GATE,
        gap("cryptographic formats use pinned official fixtures and explicit malformed vectors; unguided fuzzing is not accepted as cryptographic assurance"),
    ),
    Behavior(
        "redaction",
        "Secret and privacy redaction",
        "Known secret, credential, raw-reference, internal-note, and customer-PII canaries never cross diagnostic, replay, report, package, or audit-detail boundaries.",
        refs("internal/platform/redaction/redaction_test.go::TestSanitizeRecursivelyRedactsSensitiveFieldsAndValues"),
        refs("internal/app/redaction_leakage_test.go::TestCustomerPackageRedactionLeakageMatrix"),
        refs("internal/app/resource_bounds_test.go::TestCustomerPackageArchiveRejectsSensitiveManifestFields"),
        refs("internal/platform/redaction/redaction_test.go::TestRedactStringHandlesPrefixedCredentialsAndBoundsWork"),
        refs("internal/adapters/httpapi/router_test.go::TestReleaseRiskDecisionHTTPFlow"),
        refs("scripts/reviewer_package_workflow_check.sh"),
        RACE_GATE,
        gap("the denylist and canary classes are finite regression vectors; parser fuzzing cannot prove secret classification completeness"),
    ),
    Behavior(
        "packages",
        "Customer and release packages",
        "Packages are tenant/release scoped, deterministic, bounded, verifiable, explicitly redacted, and contain limitations and non-claims.",
        refs("internal/app/customer_package_golden_test.go::TestSampleCustomerPackageManifestGolden"),
        refs("internal/app/governance_packages_test.go::TestCustomerPackageV2ManifestSchemaAndSensitiveFieldExclusion"),
        refs("internal/app/resource_bounds_test.go::TestCustomerPackageArchiveRejectsOversizedGeneratedReport"),
        refs("internal/app/customer_package_golden_test.go::TestSampleCustomerPackageManifestGolden"),
        refs("scripts/reviewer_package_workflow_check.sh"),
        refs("scripts/black_box_release_artifact_check.sh"),
        RACE_GATE,
        gap("versioned package schemas use golden, verifier, archive-shape, and leakage matrices instead of raw-byte fuzzing"),
    ),
    Behavior(
        "backup-restore",
        "Paired backup and restore",
        "Database and object generations are captured and restored as one verified pair; mismatched, partial, or interrupted recovery fails closed.",
        refs("internal/adapters/postgres/paired_backup_restore_test.go::TestPostgresPairedBackupRestoreUsesNativeDumpAndFilesystemGeneration"),
        refs("scripts/test_paired_backup_manifest.py"),
        refs("internal/adapters/postgres/recovery_killpoints_test.go::TestRecoveryKillPointsFailClosedAndResume"),
        refs("scripts/test_paired_backup_manifest.py"),
        refs("scripts/restore_rehearsal.sh"),
        refs("scripts/black_box_demo_check.sh"),
        RACE_GATE,
        gap("backup generation mismatch and kill points are structured state-machine cases, not parser byte streams"),
    ),
    Behavior(
        "upgrade",
        "Migration and upgrade compatibility",
        "Every committed schema prefix upgrades deterministically, and legacy security state migrates conservatively without gaining trust.",
        refs("internal/adapters/postgres/migration_compatibility_test.go::TestMigrationCompatibilityFromEveryCommittedState"),
        refs("internal/adapters/postgres/migration_compatibility_test.go::TestVerificationAssuranceTaxonomyMigratesLegacyResultsConservatively"),
        refs("internal/adapters/postgres/migration_compatibility_test.go::TestOutboxDeadLetterMigrationSanitizesLegacyFailures"),
        refs("internal/adapters/postgres/migration_compatibility_test.go::TestMigrationCompatibilityFromEveryCommittedState"),
        refs("Makefile::migration-compatibility-check:"),
        gap("published-version binary and image upgrade rehearsal is intentionally tracked by EVY-1106"),
        RACE_GATE,
        gap("migration prefixes are finite committed SQL states and are validated exhaustively"),
    ),
)


def validate_reference(reference: str, root: pathlib.Path) -> list[str]:
    failures: list[str] = []
    path_text, separator, marker = reference.partition("::")
    candidate = pathlib.PurePosixPath(path_text)
    if (
        not path_text
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "\\" in path_text
    ):
        return [f"unsafe repository reference: {reference}"]
    path = (root / candidate).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return [f"reference escapes repository: {reference}"]
    if not path.is_file():
        return [f"referenced file does not exist: {reference}"]
    if separator:
        if not marker:
            failures.append(f"empty reference marker: {reference}")
        elif marker not in path.read_text(encoding="utf-8"):
            failures.append(f"reference marker does not exist: {reference}")
    return failures


def validate_evidence(
    behavior: Behavior,
    field: str,
    evidence: Evidence,
    root: pathlib.Path,
    required: bool,
) -> list[str]:
    label = f"{behavior.identifier}.{field}"
    if evidence.references and evidence.gap:
        return [f"{label}: cannot have both references and an N/A rationale"]
    if required and not evidence.references:
        return [f"{label}: requires at least one test reference"]
    if not evidence.references and len(evidence.gap.strip()) < 20:
        return [f"{label}: N/A requires a specific rationale"]
    failures: list[str] = []
    for reference in evidence.references:
        failures.extend(f"{label}: {failure}" for failure in validate_reference(reference, root))
    return failures


def validate_behaviors(
    behaviors: tuple[Behavior, ...],
    root: pathlib.Path,
    required_ids: set[str] | None = None,
) -> list[str]:
    required_ids = REQUIRED_BEHAVIOR_IDS if required_ids is None else required_ids
    identifiers = [behavior.identifier for behavior in behaviors]
    failures: list[str] = []
    if len(identifiers) != len(set(identifiers)):
        failures.append("behavior identifiers must be unique")
    missing = sorted(required_ids - set(identifiers))
    unexpected = sorted(set(identifiers) - required_ids)
    if missing:
        failures.append("missing critical behaviors: " + ", ".join(missing))
    if unexpected:
        failures.append("unexpected critical behaviors: " + ", ".join(unexpected))
    for behavior in behaviors:
        if not behavior.invariant.strip():
            failures.append(f"{behavior.identifier}: invariant is required")
        for field in ("positive", "negative", "failure"):
            failures.extend(
                validate_evidence(
                    behavior,
                    field,
                    getattr(behavior, field),
                    root,
                    required=True,
                )
            )
        for field in ("unit", "integration", "black_box", "race", "fuzz"):
            failures.extend(
                validate_evidence(
                    behavior,
                    field,
                    getattr(behavior, field),
                    root,
                    required=False,
                )
            )
    return failures


def validate_ci_contract(path: pathlib.Path) -> list[str]:
    if not path.is_file():
        return ["CI workflow does not exist"]
    body = path.read_text(encoding="utf-8")
    failures: list[str] = []
    if "name: evydence-ci-evidence-${{ github.sha }}" not in body:
        failures.append("CI coverage artifact name is not tied to github.sha")
    if "            coverage.out" not in body:
        failures.append("CI evidence artifact does not include coverage.out")
    if "run: make production-check" not in body:
        failures.append("CI does not produce coverage through production-check")
    return failures


def render(behaviors: tuple[Behavior, ...]) -> str:
    lines = [
        "# Critical Behavior Test Strategy",
        "",
        "This reference defines the repository-owned evidence required for high-trust behavior. It is generated and validated by `scripts/critical_behavior_matrix.py`; update the generator and run `scripts/critical_behavior_matrix.py --write` when the matrix or policy changes.",
        "",
        "The matrix records engineering evidence, not legal compliance, certification, complete vulnerability detection, complete SBOM coverage, or a guarantee that a release is secure.",
        "",
        "## Required Gates",
        "",
        "- `make test-strategy-check` validates every reference, the required behavior set, and the CI coverage-artifact contract.",
        "- `make coverage-check` requires live PostgreSQL, writes `coverage.out`, enforces 80.0% overall Go statement coverage, and enforces 81.0% aggregate coverage for the critical package set below.",
        "- `make production-check` additionally runs live PostgreSQL and object-store integration, race, security, recovery, benchmark, black-box, and release-artifact checks.",
        "- A percentage is never sufficient evidence by itself. Each P0 invariant must retain explicit positive, negative, and failure-path references in the matrix.",
        "",
        "## Coverage Policy",
        "",
        "The overall floor is **80.0%**. The higher critical-package aggregate floor is **81.0%** and covers these Go package prefixes:",
        "",
        "- `internal/app` and `internal/domain`;",
        "- `internal/adapters/httpapi`, `internal/adapters/postgres`, `internal/adapters/objectstore`, and `internal/adapters/verification`;",
        "- `internal/platform`.",
        "",
        "`scripts/coverage_check.sh` calculates both floors from the same `coverage.out` generated by one `go test ./... -coverpkg=./...` run. All repository Go packages are instrumented so integration tests measure the adapters and services they actually call, not just their own test package. Shared statement blocks are counted once and are covered if any test executes them; unexecuted code remains in the denominator. `make coverage` uses the same instrumentation. Measurement and floor-rejection regressions run in `make test-strategy-check`.",
        "",
        "The Go profile does not include shell/Python scripts, static site code, YAML, generated OpenAPI documents, third-party services, or external provider behavior; those surfaces require their own repository checks. No Go production package is filtered out of the overall profile, and no file-level coverage exclusion list is maintained.",
        "",
        "CI uploads `coverage.out` from the production-check job in an artifact named with `${{ github.sha }}`. That SHA identifies the exact checked-out commit (including the pull-request merge commit when GitHub tests one); it is not evidence that a branch head, tag, or later release contains the same result.",
        "",
        "## Evidence Lanes",
        "",
        "- **Positive** proves the intended behavior succeeds.",
        "- **Negative** proves a prohibited input, identity, scope, mutation, or verification result is rejected.",
        "- **Failure** proves a dependency, crash point, rollback, corruption, resource bound, or recovery path fails closed.",
        "- **Unit, integration, black-box, race, and fuzz** map where the behavior is exercised. `N/A` is allowed only with a concrete rationale; it never replaces positive, negative, or failure evidence.",
        "",
        "## Critical Behavior Matrix",
        "",
        "| ID | Behavior and invariant | Positive | Negative | Failure path | Unit | Integration | Black-box | Race | Fuzz |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for behavior in behaviors:
        lines.append(
            "| `{identifier}` | **{behavior}**<br>{invariant} | {positive} | {negative} | {failure} | {unit} | {integration} | {black_box} | {race} | {fuzz} |".format(
                identifier=behavior.identifier,
                behavior=behavior.behavior,
                invariant=behavior.invariant,
                positive=behavior.positive.render(),
                negative=behavior.negative.render(),
                failure=behavior.failure.render(),
                unit=behavior.unit.render(),
                integration=behavior.integration.render(),
                black_box=behavior.black_box.render(),
                race=behavior.race.render(),
                fuzz=behavior.fuzz.render(),
            )
        )
    lines.extend(
        [
            "",
            "## Flaky-Test Policy",
            "",
            "- Do not rerun a failed gate merely to obtain green evidence. Preserve the first failure, identify the nondeterministic dependency, and fix or explicitly ticket it.",
            "- P0 invariant tests may not be quarantined, skipped, or converted to best-effort checks. An unavailable required live dependency is a failed production gate.",
            "- Use bounded polling with explicit deadlines instead of sleeps chosen to make a race disappear. Race, contention, and recovery tests must report the seed or deterministic kill point when one exists.",
            "- A test that fails intermittently twice in 20 identical local or CI runs is treated as flaky. Stop relying on it as evidence until the root cause is fixed; record the owning ticket and affected invariant in the matrix if coverage becomes incomplete.",
            "",
            "## Deterministic Fixture Policy",
            "",
            "- Unit tests use fixed clocks, pinned schemas/trust roots, stable canonical inputs, repository-local fakes, and explicit tenant/actor identities. They do not call real providers or the public network.",
            "- Standards fixtures record source and version provenance under their testdata directory. Changing a pinned fixture requires updating its hash/provenance assertion and the parser compatibility documentation.",
            "- Live integration tests use isolated schemas, buckets, object prefixes, and test-only credentials. Cleanup must not target shared or production data.",
            "- Golden files are regenerated only through a reviewed deterministic path. A broad golden rewrite is not accepted as proof that behavior remained correct.",
            "",
            "## Maintaining The Matrix",
            "",
            "1. Add the failing/negative test at the boundary that owns the invariant.",
            "2. Add its repository-relative `file::symbol` reference to `scripts/critical_behavior_matrix.py`.",
            "3. Run `scripts/critical_behavior_matrix.py --write` and review the generated reference.",
            "4. Run `make test-strategy-check`, the affected targeted suite, and the strongest required project gate.",
            "5. Do not remove the last negative or failure-path reference for a P0 invariant without adding an equivalent replacement in the same change.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help=f"write {OUTPUT.relative_to(ROOT)}")
    parser.add_argument("--check", action="store_true", help="fail when the committed matrix differs")
    args = parser.parse_args()

    failures = validate_behaviors(BEHAVIORS, ROOT)
    failures.extend(validate_ci_contract(CI_WORKFLOW))
    if failures:
        for failure in failures:
            print(f"critical-behavior-matrix: {failure}", file=sys.stderr)
        return 1

    body = render(BEHAVIORS)
    if args.write:
        OUTPUT.write_text(body, encoding="utf-8")
        return 0
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != body:
            diff = difflib.unified_diff(
                current.splitlines(),
                body.splitlines(),
                fromfile=str(OUTPUT.relative_to(ROOT)),
                tofile="generated",
                lineterm="",
            )
            print("\n".join(diff), file=sys.stderr)
            return 1
        print(f"critical-behavior-matrix: validated {len(BEHAVIORS)} behaviors")
        return 0
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
