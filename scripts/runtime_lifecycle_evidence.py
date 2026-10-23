#!/usr/bin/env python3
"""Require real Go pass events and durable observations for every shutdown case."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PACKAGE = "github.com/aatuh/evydence/internal/platform/lifecyclecheck"
CASES = ("TestReleaseBinaryAPIGraceful", "TestReleaseBinaryAPIForced",
         "TestReleaseBinaryWorkerGraceful", "TestReleaseBinaryWorkerForced")


def verify(root, go_exit):
    errors = []
    passes = {name: 0 for name in CASES}
    package_passes = 0
    if go_exit != 0:
        errors.append("Go lifecycle command failed")
    events = root / "events.jsonl"
    if events.is_symlink() or not events.is_file():
        errors.append("Go lifecycle events are missing or unsafe")
    else:
        with events.open() as source:
            for line in source:
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict) or event.get("Package") != PACKAGE:
                        raise ValueError("invalid event owner")
                    action, name = event.get("Action"), event.get("Test")
                    if action not in ("start", "run", "pause", "cont", "output", "pass", "fail", "skip", "build-fail"):
                        raise ValueError("invalid event action")
                    if action in ("skip", "fail", "build-fail"):
                        errors.append("Go lifecycle event reported failure or skip")
                    if action == "pass":
                        if name in passes:
                            passes[name] += 1
                        elif not name:
                            package_passes += 1
                except (ValueError, TypeError):
                    errors.append("Malformed Go lifecycle event")
    if any(count != 1 for count in passes.values()) or package_passes != 1:
        errors.append("Each lifecycle case and package must pass exactly once")
    results = []
    for name in CASES:
        forced = name.endswith("Forced")
        expected = {"schema_version": "evydence-lifecycle-case.v1.0.0", "case": name,
                    "status": "passed", "forced": forced, "database_lock_barrier": True,
                    "initial_exit_code": 1 if forced else 0}
        if "API" in name:
            expected.update(process="api", restart_exit_code=0, projects=1, project_audit_entries=1,
                            completed_idempotency_records=1, post_stop_projects=0 if forced else 1,
                            writer_exclusion_during_work=True)
        else:
            expected.update(process="worker", attempts=2 if forced else 1, success_outcomes=1,
                            failure_outcomes=0, finalized_payloads=1,restart_exit_code=0 if forced else None)
        directory, receipt = root / name, root / name / "receipt.json"
        if directory.is_symlink() or receipt.is_symlink() or not receipt.is_file():
            errors.append(name + ": missing or unsafe durable receipt")
            continue
        try:
            record = json.loads(receipt.read_text())
            if not isinstance(record, dict):
                raise ValueError("invalid receipt")
            if any(type(record.get(key)) is not type(value) or record.get(key) != value
                   for key, value in expected.items()):
                raise ValueError("incorrect observations")
            if "Worker" in name:
                digest = record.get("payload_digest")
                if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                    raise ValueError("incorrect payload digest")
                expected["payload_digest"] = digest
            results.append(expected)
        except (ValueError, TypeError, OSError):
            errors.append(name + ": invalid durable observations")
    return {"schema_version": "evydence-runtime-lifecycle.v1.0.0",
            "status": "failed" if errors else "passed", "cases": results, "errors": errors}


def main():
    root = Path(sys.argv[1])
    result = verify(root, int(sys.argv[2]))
    result["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    result["worktree_clean"] = not subprocess.check_output(["git", "status", "--porcelain"], text=True)
    result["binaries"] = []
    for name in ("api", "worker"):
        path=Path(os.environ["EVYDENCE_LIFECYCLE_"+name.upper()+"_BIN"])
        digest=hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda:source.read(1024*1024),b""):
                digest.update(chunk)
        result["binaries"].append({"name":name,"sha256":"sha256:"+digest.hexdigest(),"bytes":path.stat().st_size})
    result["limitations"] = ["Release-style local binaries; not published release assets.",
        "Disposable PostgreSQL schemas and filesystem objects; no live external providers or cluster.",
        "Lease expiry is advanced only in the isolated forced-worker fixture."]
    target = root / "summary.json"
    with target.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print("runtime-lifecycle-check: " + result["status"] + "; cases=" + str(len(result["cases"])))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
