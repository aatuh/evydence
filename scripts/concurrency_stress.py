#!/usr/bin/env python3
"""Run explicit stress cases and reject missing, skipped or failed evidence."""
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CPUS = (1, 2, 4)
CASES = {
    "./internal/app": (
        "TestWithIdempotencyConcurrentReleaseBundleCommitsOneEffectAndReplay",
        "TestWithIdempotencyConcurrentScopesDoNotCollide",
        "TestWithIdempotencyConcurrentDifferentBodiesRunsOnlyOwner",
        "TestWithIdempotencyCanceledWaiterDoesNotRunOrReserve",
        "TestWithIdempotencyRecoversExpiredPendingAfterProcessRestart",
        "TestReleaseEvidenceWriteDoesNotPublishBeforeUnitOfWorkCommit",
    ),
    "./internal/adapters/httpapi": (
        "TestCreateProductConcurrentIdempotencyRetriesOneStoredResponse",
    ),
    "./internal/adapters/postgres": (
        "TestStoreConcurrentIdempotencyAcrossLedgerInstances",
        "TestPostgresAuditRepositoryAllocatesStrictConcurrentSequences",
        "TestPostgresReleaseRepositoryRejectsStaleConcurrentRevision",
        "TestOutboxDeduplicatesReclaimsDeadLettersAndAuditsReplay",
    ),
    "./internal/platform/wiring": (
        "TestPostgresCatalogCreationNativeConcurrentReplayCreatesOnce",
        "TestPostgresSigningKeyCommandsAreAtomicTenantSafeAndSerialized",
        "TestPostgresCustomerCreationConcurrentReplayGeneratesOnce",
        "TestPostgresCustomerPackageAccessCommitsCountAndAuditWithoutLedger",
        "TestPostgresSessionReplacementKeepsHistoryAndInvalidatesOldCredential",
        "TestPostgresWorkerReplicasClaimEachJobOnce",
    ),
}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_summary(directory, summary):
    # Replace only our fixed evidence file; never follow an existing symlink.
    with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as out:
        json.dump(summary, out, indent=2, sort_keys=True)
        out.write("\n")
    os.replace(out.name, directory / "summary.json")


def main():
    os.chdir(ROOT)
    directory = ROOT / "tmp/concurrency-stress"
    if directory.is_symlink():
        raise ValueError("stress evidence directory must not be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    summary = {"schema_version": "evydence-concurrency-stress.v1.0.0",
               "status": "failed", "started_at": timestamp(), "schedulers": CPUS,
               "cases": CASES, "claim": "local repeated single-writer and worker contention checks only"}
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        raw_count = os.environ.get("EVYDENCE_CONCURRENCY_STRESS_ITERATIONS", "10")
        if not re.fullmatch(r"[0-9]{1,4}", raw_count) or not 1 <= int(raw_count) <= 1000:
            raise ValueError("EVYDENCE_CONCURRENCY_STRESS_ITERATIONS must be 1 through 1000")
        if not os.environ.get("EVYDENCE_TEST_DATABASE_URL", "").strip():
            raise ValueError("EVYDENCE_TEST_DATABASE_URL is required; live coverage cannot skip")
        count = int(raw_count)
        expected = {(f"github.com/aatuh/evydence/{package[2:]}", name)
                    for package, names in CASES.items() for name in names}
        names = [name for tests in CASES.values() for name in tests]
        command = ["go", "test", "-json", "-race", "-p=1", "-cpu=1,2,4",
                   f"-count={count}", "-timeout=30m", "-run", "^(" + "|".join(names) + ")$", *CASES]
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
        tree = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=False)
        summary.update(commit=head.stdout.strip() if head.returncode == 0 else "unknown",
                       worktree_clean=not tree.stdout.strip() if tree.returncode == 0 else None,
                       iterations=count, passes_per_test=count * len(CPUS))
        passed = Counter()
        invalid = False
        # Preserve streaming raw evidence without retaining test output in RAM.
        fd = os.open(directory / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as evidence:
            summary["status"] = "running"
            write_summary(directory, summary)
            child = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, start_new_session=True)
            try:
                for line in child.stdout:
                    evidence.write(line)
                    try:
                        event = json.loads(line)
                        key = (event.get("Package"), event.get("Test"))
                        if event.get("Action") in ("fail", "skip"):
                            invalid = True
                        if event.get("Action") == "pass" and key in expected:
                            passed[key] += 1
                    except (ValueError, AttributeError):
                        invalid = True
                code = child.wait()
            finally:
                child.stdout.close()
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
        summary["go_exit_code"] = code
        summary["passed_counts"] = {package + "::" + name: passed[(package, name)]
                                    for package, name in sorted(expected)}
        if code != 0 or invalid or any(passed[key] != count * len(CPUS) for key in expected):
            raise ValueError("failed, skipped, malformed or incomplete stress evidence; inspect tmp/concurrency-stress/events.jsonl")
        summary["status"] = "passed"
        print(f"concurrency-stress: {len(expected)} tests passed {count * len(CPUS)} times each under race (cpu=1,2,4)")
        return 0
    except KeyboardInterrupt:
        print("concurrency-stress: interrupted; owned child stopped", file=sys.stderr)
        return 130
    except (OSError, ValueError) as error:
        # Diagnostics never include database URLs, env dumps or subprocess args.
        message = str(error) if isinstance(error, ValueError) else "could not execute stress gate"
        print("concurrency-stress: " + message, file=sys.stderr)
        return 1
    finally:
        if summary["status"] != "passed":
            summary["status"] = "failed"
        summary["finished_at"] = timestamp()
        write_summary(directory, summary)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
