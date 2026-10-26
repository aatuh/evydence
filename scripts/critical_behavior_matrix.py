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
    "worker-shutdown",
    "http-shutdown",
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
        refs("internal/app/identity_fuzz_test.go::FuzzIdempotencyRecordKeyRoundTrip",
             "internal/app/identity_fuzz_test.go::FuzzParseIdempotencyRecordKey"),
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
        refs("internal/app/fuzz_test.go::FuzzValidDigest",
             "internal/app/identity_fuzz_test.go::FuzzObjectPayloadKeyRoundTrip",
             "internal/app/identity_fuzz_test.go::FuzzParseObjectPayloadKey"),
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
            "internal/app/parsers/spdx/fuzz_test.go::FuzzSPDX",
            "internal/app/parsers/vex/parser_test.go::FuzzVEX",
            "internal/app/parsers/scanners/parser_test.go::FuzzParseBounded",
            "internal/app/parsers/scanners/fuzz_test.go::FuzzProbeReleaseID",
            "internal/app/openapi_fuzz_test.go::FuzzOpenAPIContract",
            "cmd/evydence-worker/openapi_fuzz_test.go::FuzzReplayedOpenAPIContract",
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
        refs(
            "internal/adapters/verification/dsse/fuzz_test.go::FuzzDSSEEnvelope",
            "internal/adapters/verification/sigstore/fuzz_test.go::FuzzSigstoreBundle",
            "internal/verification/app/integrity_fuzz_test.go::FuzzMerkleBatchIntegrity",
            "internal/verification/app/integrity_fuzz_test.go::FuzzReleaseBundleIntegrity",
            "internal/verification/app/native_inspection_fuzz_test.go::FuzzAuditChainIntegrity",
            "internal/verification/app/native_inspection_fuzz_test.go::FuzzEvidenceCanonicalIntegrity",
            "internal/verification/app/native_inspection_fuzz_test.go::FuzzArtifactSignatureMetadata",
            "internal/verification/app/native_inspection_fuzz_test.go::FuzzBackupManifestRecordedChecks",
            "internal/verification/app/checkpoint_fuzz_test.go::FuzzMerkleCheckpointIntegrity",
            "internal/verification/app/checkpoint_fuzz_test.go::FuzzReleaseManifestCheckpointIntegrity",
            "internal/verification/app/native_binding_fuzz_test.go::FuzzDSSESnapshotBinding",
            "internal/verification/app/native_binding_fuzz_test.go::FuzzCosignSnapshotBinding",
            "internal/verification/app/retention_fuzz_test.go::FuzzRetentionObservation",
            "internal/verification/app/subject_dispatch_fuzz_test.go::FuzzSubjectVerificationDispatch",
            "internal/experimental/app/public_transparency_fuzz_test.go::FuzzPublicTransparencyProof",
            "cmd/evydence/verification_fuzz_test.go::FuzzReleaseManifest",
        ),
    ),
    Behavior(
        "redaction",
        "Secret and privacy redaction",
        "Known secret, credential, raw-reference, internal-note, and customer-PII canaries never cross diagnostic, replay, report, package, or audit-detail boundaries.",
        refs("internal/platform/redaction/redaction_test.go::TestSanitizeRecursivelyRedactsSensitiveFieldsAndValues", "internal/platform/logging/logging_test.go::TestAllEventsOmitSecretCanariesAndPreserveStructuredIdentity"),
        refs("internal/app/redaction_leakage_test.go::TestCustomerPackageRedactionLeakageMatrix", "internal/adapters/httpapi/logging_test.go::TestRequestLoggingOmitsSecretsAndCorrelatesAuthorizedCommand"),
        refs("internal/app/resource_bounds_test.go::TestCustomerPackageArchiveRejectsSensitiveManifestFields", "internal/adapters/postgres/logging_test.go::TestAuditLoggingDoesNotPublishSuccessAfterFailedCommit"),
        refs("internal/platform/redaction/redaction_test.go::TestRedactStringHandlesPrefixedCredentialsAndBoundsWork"),
        refs("internal/adapters/httpapi/router_test.go::TestReleaseRiskDecisionHTTPFlow", "cmd/evydence-worker/logging_postgres_test.go::TestHTTPToNativeWorkerLoggingCorrelatesDurableSideEffect"),
        refs("scripts/reviewer_package_workflow_check.sh"),
        RACE_GATE,
        gap("the denylist and canary classes are finite regression vectors; parser fuzzing cannot prove secret classification completeness"),
    ),
    Behavior(
        "packages",
        "Customer and release packages",
        "Packages are tenant/release scoped, deterministic, bounded, verifiable, explicitly redacted, and contain limitations and non-claims.",
        refs("internal/app/customer_package_golden_test.go::TestSampleCustomerPackageManifestGolden"),
        refs("internal/app/governance_packages_test.go::TestCustomerPackageV2ManifestSchemaAndSensitiveFieldExclusion",
             "cmd/evydence/verification_fuzz_test.go::TestPackageCoverageRejectsUnspecifiedBundleEvidence"),
        refs("internal/app/resource_bounds_test.go::TestCustomerPackageArchiveRejectsOversizedGeneratedReport"),
        refs("internal/app/customer_package_golden_test.go::TestSampleCustomerPackageManifestGolden"),
        refs("scripts/reviewer_package_workflow_check.sh"),
        refs("scripts/black_box_release_artifact_check.sh"),
        RACE_GATE,
        refs("cmd/evydence/verification_fuzz_test.go::FuzzCustomerPackageManifest",
             "cmd/evydence/verification_fuzz_test.go::FuzzCustomerPackageArchive",
             "cmd/evydence/verification_fuzz_test.go::FuzzReleaseManifest"),
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
    Behavior(
        "worker-shutdown",
        "Bounded worker shutdown and lease recovery",
        "Signals stop admission; active work drains within one budget, and uncertain work remains lease-fenced and retryable without false acknowledgement.",
        refs("cmd/evydence-worker/worker_loop_test.go::TestWorkerLoopShutdownAllowsActiveJobToFinishBeforeCancellation"),
        refs("cmd/evydence-worker/worker_loop_test.go::TestWorkerLoopShutdownDoesNotStartClaimedBatchTail"),
        refs("cmd/evydence-worker/worker_loop_test.go::TestWorkerLoopShutdownBoundsUncooperativeProcessor"),
        refs("cmd/evydence-worker/worker_loop_test.go::TestWorkerLoopSignalProcess"),
        refs("cmd/evydence-worker/worker_loop_postgres_test.go::TestWorkerLoopShutdownPostgresLeaseReclaimAndNativeIdempotency"),
        refs("internal/platform/lifecyclecheck/shutdown_test.go::TestReleaseBinaryWorkerGraceful", "internal/platform/lifecyclecheck/shutdown_test.go::TestReleaseBinaryWorkerForced"),
        RACE_GATE,
        gap("signal, deadline and lease states use controlled barriers and real storage; parser byte fuzzing does not model process lifetime"),
    ),
    Behavior(
        "http-shutdown",
        "HTTP admission and bounded request drain",
        "Admitted requests finish before graceful cleanup; new connections are rejected, and serve/deadline failures cancel or drain work without hiding errors.",
        refs("cmd/evydence-api/http_lifecycle_test.go::TestHTTPDrainActiveRequestCompletesAndRejectsNewWork"),
        refs("cmd/evydence-api/http_lifecycle_test.go::TestHTTPDrainDeadlineCancelsRequestAndReturnsFailure"),
        refs("cmd/evydence-api/http_lifecycle_test.go::TestHTTPDrainServeFailureWaitsForAdmittedRequest"),
        refs("cmd/evydence-api/http_lifecycle_test.go::TestHTTPDrainStatusOmitsRawFailureDetails"),
        refs("cmd/evydence-api/http_lifecycle_test.go::TestHTTPDrainClosesIdleKeepAliveConnection"),
        refs("internal/platform/lifecyclecheck/shutdown_test.go::TestReleaseBinaryAPIGraceful", "internal/platform/lifecyclecheck/shutdown_test.go::TestReleaseBinaryAPIForced"),
        RACE_GATE,
        gap("controlled signals, listener failures and connection barriers model lifecycle states; byte fuzzing does not model shutdown ownership"),
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
        "- `make concurrency-stress-check` requires live PostgreSQL and repeats the explicit contention cases under race with CPU settings 1, 2 and 4. It rejects missing or skipped test evidence.",
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
            "## Foundational Property Tests",
            "",
            "`internal/application/normalized_json_fuzz_test.go` exercises the existing float64 normalized-JSON hash profile, parse/serialize stability and changed-field detection. It does not introduce RFC 8785/JCS or change historical hashes. `internal/platform/jsonbounds/fuzz_test.go` covers bounded JSON round trips and duplicate decoded keys with different escape spellings. These JSON callbacks bound input and structural work before generic decoding.",
            "",
            "`internal/app/identity_fuzz_test.go` covers exact tenant object-key ownership, canonical object-key parsing, opaque idempotency-field round trips and readable legacy record keys. Each callback limits input size; existing digest targets also retain explicit work limits. `TestFoundationalFuzzCoverage` checks that all seven foundational targets remain declared and seeded; actual seed/campaign execution supplies behavioral evidence.",
            "",
            "Ordinary `go test ./...` includes fuzz seed corpora. The dedicated `make fuzz-smoke` target additionally accounts for every registered target and seed, including database DSN parsing, through the bounded runner described below. Bounded fuzz runs supplement deterministic positive, negative and failure vectors and do not establish exhaustive parser, authorization or cryptographic assurance.",
            "",
            "## Evidence Parser Property Tests",
            "",
            "Seven bounded parser targets exercise CycloneDX 1.6 SBOMs, SPDX 2.2/2.3, OpenVEX and CycloneDX VEX 1.4 through 1.7, all five admitted scanner envelopes, scanner scope probing, and the production OpenAPI ingestion and worker-replay owners. Existing source-provenanced fixtures retain their bytes, licenses and version scope; generated version variants remain synthetic seeds. `TestEvidenceParserFuzzCoverage` protects target declarations and seeds, while package tests and serial campaigns supply behavioral evidence.",
            "",
            "Successful parses must remain repeatable after JSON serialization, with number spelling preserved before re-decoding. Streaming parsers and scope probes also receive partial readers. Accepted inputs produce duplicate-key and over-budget rejection cases. SPDX checksum and external-reference limits apply per package; aggregate document work remains bounded by its byte/value limits. Scope probing extracts authorization scope before full scanner normalization and does not claim to validate a report.",
            "",
            "CycloneDX preserves its original 256 KiB input profile, default depth/string limits and existing count budgets; other parser callbacks cap input at 64 KiB. Format-specific structural and result-count budgets bound parser work; the OpenAPI JSON harness separately limits shape before calling its production owner. These harness budgets do not narrow production acceptance. Positive HTML-escaping seeds check that expanded serialized bytes fail the original byte budget, then retain the same projection with a budget matching the new encoding; structural/count limits stay unchanged. OpenAPI duplicate-key regressions exercise root, nested and escaped spellings in ingestion and replay, alongside digest/size binding and existing YAML-compatibility characterization. No fuzz callback contacts a provider, opens a database or uses customer data. Cryptographic/archive properties and complete campaign orchestration appear below.",
            "",
            "## Cryptographic and Archive Property Tests",
            "",
            "Eight targets exercise the production DSSE/Sigstore adapters, native Merkle and release-bundle inspectors, public transparency proof math/entry binding, and offline CLI package/ZIP/release verification. They retain the pinned official Sigstore bundle/trusted root, in-toto fixture and existing RFC6962-style irregular-tree vector. Deterministic synthetic Ed25519 keys and independent recursive Merkle/RFC6962 reference projections supply positive vectors without production credentials. Aggregate compatibility tests remain unchanged.",
            "",
            "Assertions target signed payload/type, subject/identity policy, coverage, artifact bytes, root/proof, signature and manifest-hash changes. JSON envelope whitespace, key order and unsigned hints are not treated as cryptographically signed bytes. CLI duplicate-key mutations repeat an actual decoded input key, preserving existing key-case handling. The customer-package coverage regression uses correctly hashed and signed bundles to prove that missing, null, empty or unusable evidence IDs cannot establish coverage of a package's declared evidence.",
            "",
            "DSSE/Sigstore JSON inputs cap at 64 KiB and bound nested structure/signature work; native integrity data caps at 4 KiB with at most 16 leaves. Public proof inputs cap at 16 KiB, retain the 64-node production proof bound and generate at most 16 reference leaves. CLI manifest/artifact input caps at 16 KiB. ZIP inputs cap at 128 KiB compressed, 16 entries, 128 KiB per member and 512 KiB actual expansion before the production reader runs; stored/deflated positive archives and duplicate/traversal/symlink/unexpected entries are covered. Files stay in isolated test directories and archives are never extracted. No callback accesses ambient credentials, databases or providers.",
            "",
            "These bounded campaigns supplement fixed cryptographic and negative-vector suites. They do not establish cryptographic assurance, exhaustive attack coverage, external publisher identity or public-log trust. Offline included-key checks establish local consistency against supplied material; the existing operator trust and identity policies remain authoritative. The runner below supplies complete smoke/campaign accounting, scheduling and bounded retention.",
            "",
            "## Native Verification Properties And Owner Census",
            "",
            "The evidence-input scope below covers implemented evidence document parsers, offline package/release verifiers, signature/proof adapters and native verification commands. Authentication protocols, application configuration, provider signing APIs and general report generation are separate boundaries, not evidence parser/verifier owners. Native bindings are listed separately from lower-level algorithms so adapter coverage cannot stand in for an unexecuted command.",
            "",
            "| Concrete owner (relative to repository root) | Executing property target |",
            "| --- | --- |",
            "| `internal/app/parsers/cyclonedx`: bounded CycloneDX SBOM parser | `FuzzCycloneDX` |",
            "| `internal/app/parsers/spdx`: bounded SPDX parser | `FuzzSPDX` |",
            "| `internal/app/parsers/vex`: OpenVEX and CycloneDX VEX parsers | `FuzzVEX` |",
            "| `internal/app/parsers/scanners`: all admitted scanner envelopes and release scope probe | `FuzzParseBounded`, `FuzzProbeReleaseID` |",
            "| `internal/app`: OpenAPI ingestion parser | `FuzzOpenAPIContract` |",
            "| `cmd/evydence-worker`: OpenAPI replay parser | `FuzzReplayedOpenAPIContract` |",
            "| `internal/adapters/verification/dsse`: envelope, PAE, in-toto and configured root policy | `FuzzDSSEEnvelope`, `FuzzDSSESnapshotBinding` |",
            "| `internal/verification/app/dsse_verification.go` and `internal/adapters/verification/dsseobjects`: native snapshot, bounded object and policy binding | `FuzzDSSESnapshotBinding` |",
            "| `internal/adapters/verification/sigstore`: offline bundle, certificate identity and inclusion verification | `FuzzSigstoreBundle`, `FuzzCosignSnapshotBinding` |",
            "| `internal/verification/app/cosign_commands.go` and `internal/adapters/verification/cosignobjects`: native snapshot, bounded object and receipt binding | `FuzzCosignSnapshotBinding` |",
            "| `internal/verification/app/audit_chain_verification.go`: paged audit inspector and command, including historical canonical hashes | `FuzzAuditChainIntegrity` |",
            "| `internal/verification/app/evidence_verification.go`: canonical evidence inspector and command, including versioned lifecycle origins | `FuzzEvidenceCanonicalIntegrity` |",
            "| `internal/verification/app/artifact_signature_verification.go`: metadata inspector and command | `FuzzArtifactSignatureMetadata` |",
            "| `internal/verification/app/backup_verification.go`: recorded manifest inspector and command | `FuzzBackupManifestRecordedChecks` |",
            "| `internal/verification/app/merkle_verification.go`: Merkle inspector and command | `FuzzMerkleBatchIntegrity`, `FuzzMerkleCheckpointIntegrity` |",
            "| `internal/verification/app/release_bundle_verification.go`: release-bundle inspector and command | `FuzzReleaseBundleIntegrity`, `FuzzReleaseManifestCheckpointIntegrity` |",
            "| `internal/verification/app/merkle_checkpoint_verification.go`: checkpoint bound to the actual inspected audit pages | `FuzzMerkleCheckpointIntegrity` |",
            "| `internal/verification/app/release_manifest_checkpoint.go`: signed manifest checkpoint and covered audit head | `FuzzReleaseManifestCheckpointIntegrity` |",
            "| `internal/verification/app/retention.go`: observation assessment and recorded custody freshness | `FuzzRetentionObservation` |",
            "| `internal/verification/app/subject_verification.go`: closed dispatch and current scope replay guard | `FuzzSubjectVerificationDispatch` |",
            "| `internal/experimental/app`: public transparency proof and entry binding | `FuzzPublicTransparencyProof` |",
            "| `cmd/evydence`: customer package manifest, evidence-bundle coverage, ZIP members and metadata | `FuzzCustomerPackageManifest`, `FuzzCustomerPackageArchive` |",
            "| `cmd/evydence`: release artifact manifest and detached Ed25519 signature | `FuzzReleaseManifest` |",
            "",
            "Ten additional native targets use at most 4 KiB of generated content each; dispatch instead bounds the combined kind/ID input at 8 KiB and tests the unchanged production scalar limits. Audit/checkpoint callbacks generate at most eight one-entry pages and one audit-entry signature, with bounded production page/byte checks and deterministic synthetic signing keys. DSSE objects remain below 64 KiB with one root, one signature and fixed required claims. Cosign uses the existing pinned public Sigstore bundle and local trust root. Snapshot, observation, output and receipt repetition must be stable, and controlled tampering must preserve a failed or limited verdict. The architecture floor independently requires each native target to remain declared and seeded; actual smoke/campaign execution is separate evidence.",
            "",
            "Artifact metadata remains `limited`; it never gains a cryptographic pass. Backup checks assess recorded consistency rather than rehashing live exports or proving restoration. Retention uses clearly synthetic observation ports to test native status, recorded hash and expiry behavior; a positive synthetic assessment is not a live WORM/provider observation. Child ports in the dispatch property return no assurance state and prove forwarding only. Other transaction ports model bounded immutable snapshots and atomic append-only receipt/audit/outbox capture, using the actual authorization policies, canonical hashing and signature adapters. They do not replace required real persistence checks. No callback loads a Ledger aggregate, opens a database, reads credentials or contacts a provider.",
            "",
            "## Fuzz Runner And Corpus Policy",
            "",
            "`scripts/fuzz-targets.json` registers 35 reviewed synthetic/public targets. `scripts/fuzz_driver.py` compares this registry with native `go test -list '^Fuzz' ./...` discovery. Missing, extra or duplicate targets fail before campaigns. Smoke runs require one run/pass per target and each observed seed, at least one seed per target, and one package pass; skipped, failed, malformed or incomplete evidence cannot pass. Campaigns additionally require completed baseline coverage, exactly one worker and observed mutation executions beyond that baseline. Driver and workflow regressions run through `make fuzz-driver-check` and `make test-strategy-check`.",
            "",
            "Local Go commands must reserve the host RAM coordinator for the entire foreground operation. Run `\"$HOME/.local/bin/codex-ramgate\" 4 -- make fuzz-smoke` or `\"$HOME/.local/bin/codex-ramgate\" 4 -- make fuzz-campaign-short`. Do not nest reservations when a larger gate already encloses the command. The short campaign runs every target serially for three seconds; it does not select a subset or retry failures.",
            "",
            "The driver accepts only `smoke` or `campaign`, a Go executable, `--seconds` (1–60, default 3), `--timeout` (1–1200 seconds per command, default 600) and `--budget` (1–2700 seconds overall, default 1800). It forces `GOMAXPROCS=1`, `-p=1`, `-parallel=1`, `-count=1`, local toolchain selection, read-only modules, `GOGC=50` and a 512 MiB Go soft memory limit. A deadline, interruption or protocol failure terminates and waits for the owned process group. Campaigns never run concurrently. The soft Go limit is not a hard process-memory ceiling; reserve conservatively and use an external cgroup where required.",
            "",
            "The PR/push workflow `.github/workflows/fuzz.yml` runs complete smoke seeds; the weekly Sunday 03:17 UTC schedule runs each target for 30 seconds. One foreground cgroup caps the whole job command at 4096 MiB with no swap. `setpriv` drops UID/GID, supplementary groups, capabilities and privilege escalation without PAM session migration; it resets the environment before restoring only the selected toolchain PATH. Before Go starts, the ordinary runner process verifies its expected cgroup path, `memory.max=4294967296` and `memory.swap.max=0`; missing or ineffective limits fail the job. The driver budget is 2400 seconds, each command is capped at 600 seconds, and the workflow timeout is 45 minutes. The workflow uses pinned Actions, a read-only repository token, checkout without persistent credentials and no publisher secrets, environments or manual-dispatch trigger. Configuration alone does not prove a hosted run succeeded or establish a required branch-protection check.",
            "",
            "Each fresh `tmp/fuzz/<mode>-<unique>/public/summary.json` records commit, tree, working-tree cleanliness, a SHA-256 over tracked and nonignored source names/content/executable bits, Go version, settings, target/seed/execution accounting and terminal status. Source changes during a successful run fail qualification. PR summaries identify the tested merge commit; they do not silently claim qualification of another head. Raw Go events and stderr remain in the sibling `private/` directory and are excluded from artifact uploads. Event files are limited to 32 MiB per command and lines to 1 MiB.",
            "",
            "Only reviewable synthetic/public fixtures may enter the registry, callbacks, `f.Add` seeds or `testdata/fuzz/<target>` corpora. Never use customer evidence, production DSNs, private keys, tokens or provider payloads. A target registration requires reviewing its input/output and crash privacy. The DSN callback preserves the existing 8 MiB accepted-input budget and uses invented credentials; the parser does not connect to a database or inspect ambient credential files. Other target-specific bounds remain documented above.",
            "",
            "New Go-format crash files are retained even when the command fails or times out. Corpus paths reject symlinks; each corpus has at most 128 regular files of at most 1 MiB. A run copies at most 16 new/changed hexadecimal-named crash inputs, each at most 1 MiB, to content-addressed files under `public/crashes/`, recording package, target, size and SHA-256. Oversize, excessive or unsafe artifacts fail the run rather than being silently omitted. Existing inputs and previous run directories are preserved.",
            "",
            "GitHub uploads only `tmp/fuzz/*/public/` with 14-day retention and an exact-SHA artifact name. Artifacts in this public repository may be publicly accessible: the retention policy is not a confidentiality boundary. Reproduce failures privately with synthetic data, assess impact before publishing regressions, and follow [SECURITY.md](../../SECURITY.md) and the [security response procedure](security-response.md) for suspected vulnerabilities. The runner never creates issues, advisories or severity claims. Finite campaign observations are regression evidence, not exhaustive parser coverage, legal compliance or cryptographic assurance.",
            "",
            "## Repeated Concurrency Gate",
            "",
            "Run `make concurrency-stress-check` with `EVYDENCE_TEST_DATABASE_URL` pointing to a disposable local PostgreSQL database. The gate also runs inside `make production-check` and in the separate `Race and Stress` CI job. It preserves EVY-303's application/HTTP/independent-store idempotency cases and adds native catalog, audit sequence, stale revision, signing-key rotation, customer-package generation/access, session replacement and worker-claim coverage. The native paths do not load the retired production Ledger aggregate; retained aggregate tests are compatibility oracles.",
            "",
            "`EVYDENCE_CONCURRENCY_STRESS_ITERATIONS` defaults to `10` and accepts integers `1..1000`. Each selected test runs that many times at each of `-cpu=1,2,4` under `-race`, giving 30 passes per test at the default. `-p=1` serializes independent package binaries without changing contention inside tests. Use one iteration for focused development; ticket acceptance uses the default. The per-package watchdog remains 30 minutes. There are no retries that can erase a failure.",
            "",
            "The explicit selection in `scripts/concurrency_stress.py` is checked against real test symbols. New native cases use start barriers, a fixed package clock/injected IDs, and a held PostgreSQL row lock rather than sleeps: competing replicas must drain unlocked jobs before the held job is released. Package replay must commit one package, audit and receipt while foreign-tenant requests leave no effect. Existing lifecycle cases cover lease reclamation and immediate credential invalidation after replacement.",
            "",
            "`tmp/concurrency-stress/events.jsonl` retains streaming Go test events; `summary.json` records commit, working-tree cleanliness, scheduler/count settings and per-test passes. Missing, skipped, malformed, failed or interrupted evidence fails the gate. CI artifacts include `${{ github.sha }}` in their name. A configured workflow is not proof of a successful hosted run or a required branch-protection context; verify both separately before closing EVY-1105. These tests support the single API writer and worker-contention profile, not multi-writer API safety or production capacity.",
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
