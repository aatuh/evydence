#!/usr/bin/env python3
"""Prove request-only G124 filtering retains both response-cookie alerts."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import yaml

from support_matrix import load_policy
from support_matrix_artifacts import UniqueLoader

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    policy = load_policy(root)
    config_path = root / ".golangci.yml"
    config_bytes = config_path.read_bytes()
    config = yaml.load(config_bytes, Loader=UniqueLoader)
    if "gosec" not in config["linters"]["enable"]:
        raise ValueError("project configuration does not enable gosec")
    fixtures = root / "scripts/testdata/lint-policy"
    expected = set()
    for name, marker in (("response.go.txt", "G124_PRODUCTION_RESPONSE"), ("request_test.go.txt", "G124_TEST_RESPONSE")):
        lines = (fixtures / name).read_text().splitlines()
        matches = [index for index, line in enumerate(lines, 1) if marker in line]
        if len(matches) != 1:
            raise ValueError("invalid cookie analyzer control")
        expected.add((name.removesuffix(".txt"), matches[0]))
    with tempfile.TemporaryDirectory(prefix="evydence-lint-policy-") as directory:
        work = Path(directory)
        environment = dict(os.environ, GOWORK="off")
        (work / "go.mod").write_text("module evydence.invalid/lint-policy\n\ngo " + policy["go"]["minimum"] + "\n\ntoolchain go" + policy["go"]["current"] + "\n")
        for name in ("response.go.txt", "request_test.go.txt"):
            shutil.copyfile(fixtures / name, work / name.removesuffix(".txt"))
        compiler = subprocess.check_output(["go", "env", "GOVERSION"], cwd=work, env=environment, text=True, timeout=30).strip()
        if compiler not in {"go" + policy["go"]["minimum"], "go" + policy["go"]["current"]}:
            raise ValueError("unsupported characterization compiler")
        name = "TestRequestCookiesCarryOnlyNameValue"
        test = subprocess.run(["go", "test", "./...", "-json", "-run", "^" + name + "$", "-count=1", "-timeout=1m"], cwd=work, env=environment, capture_output=True, text=True, timeout=120)
        if test.returncode:
            raise ValueError("cookie-header characterization failed")
        events = [json.loads(line) for line in test.stdout.splitlines()]
        passed = [event for event in events if event.get("Test") == name and event.get("Action") == "pass"]
        if len(passed) != 1 or any(event.get("Action") in {"skip", "fail"} for event in events):
            raise ValueError("cookie-header characterization did not execute")
        report = work / "issues.json"
        command = ["golangci-lint", "run", "--config", str(root / ".golangci.yml"), "--enable-only=gosec", "--max-same-issues=0", "--max-issues-per-linter=0", "--output.json.path", str(report), "--output.text.path", str(work / "issues.log"), "./..."]
        result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True, timeout=180)
        summary = {"schema_version": "evydence-lint-policy.v1", "status": "failed",
                   "configuration_sha256": hashlib.sha256(config_bytes).hexdigest(),
                   "compiler": compiler, "characterization_named_passes": len(passed),
                   "characterization_exit_code": test.returncode, "analyzer_exit_code": result.returncode,
                   "expected_response_findings": sorted(expected), "observed_findings": []}
        evidence = root / "tmp/lint-policy-check"
        evidence.mkdir(parents=True, exist_ok=True)
        def save():
            pending = evidence / "summary.new"
            pending.write_text(json.dumps(summary, indent=2) + "\n")
            pending.replace(evidence / "summary.json")
        save()
        if result.returncode != 1 or not report.is_file():
            raise ValueError("cookie analyzer controls did not produce findings")
        issues = json.loads(report.read_text())["Issues"]
        summary["observed_findings"] = [{"linter": item["FromLinter"], "file": Path(item["Pos"]["Filename"]).name,
                                         "line": item["Pos"]["Line"], "rule": item["Text"].split(":", 1)[0]} for item in issues]
        save()
        if any(item["FromLinter"] != "gosec" or not item["Text"].startswith("G124:") for item in issues):
            raise ValueError("unexpected cookie analyzer finding")
        actual = [(Path(item["Pos"]["Filename"]).name, item["Pos"]["Line"]) for item in issues]
        if len(actual) != len(expected) or set(actual) != expected:
            raise ValueError("request-only filter hid a response alert or retained a request false positive")
        summary["status"] = "passed"
        save()
    print("lint-policy-check: request header unchanged; insecure production/test responses both detected")


if __name__ == "__main__":
    try:
        check()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print("lint-policy-check: cookie-header or analyzer controls failed", file=sys.stderr)
        sys.exit(1)
