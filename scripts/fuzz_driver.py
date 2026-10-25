#!/usr/bin/env python3
"""Run the registered fuzz set serially and retain bounded, source-bound evidence."""
from collections import Counter
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/aatuh/evydence"
MAX_LOG = 32 << 20
MAX_LINE = 1 << 20
MAX_CRASH = 1 << 20
MAX_CRASHES = 16


class DriverError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise DriverError("invalid_arguments")


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def number(value):
    if not re.fullmatch(r"[0-9]{1,4}", value):
        raise DriverError("invalid_settings")
    return int(value)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DriverError("duplicate_json_key")
        value[key] = item
    return value


def safe_path(root, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(p in (".", "..") for p in path.parts):
        raise DriverError("unsafe_path")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise DriverError("symlink_path")
    return current


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise DriverError("file_budget")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise DriverError("file_budget")
        return raw


def registry(root):
    path = safe_path(root, "scripts/fuzz-targets.json")
    document = json.loads(read_regular(path, 256 << 10), object_pairs_hook=unique_object)
    if not isinstance(document, dict) or set(document) != {"schema", "artifact_policy", "targets"} or document["schema"] != "evydence-fuzz-targets.v1" or document["artifact_policy"] != "synthetic-public-v1":
        raise DriverError("invalid_registry")
    targets = document["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 128:
        raise DriverError("invalid_registry")
    seen = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"package", "name"}:
            raise DriverError("invalid_registry")
        package, name = target["package"], target["name"]
        if not isinstance(package, str) or not re.fullmatch(r"\./(?:cmd|internal)/[A-Za-z0-9_/-]{1,180}", package) or "//" in package:
            raise DriverError("invalid_package")
        if not isinstance(name, str) or not re.fullmatch(r"Fuzz[A-Z0-9_][A-Za-z0-9_]{0,120}", name):
            raise DriverError("invalid_target")
        safe_path(root, package[2:])
        key = (package, name)
        if key in seen:
            raise DriverError("duplicate_target")
        seen.add(key)
    return sorted(targets, key=lambda t: (t["package"], t["name"]))


def git(root, *args):
    child = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    if child.returncode or len(child.stdout) > 4 << 20:
        raise DriverError("source_identity")
    return child.stdout


def source_identity(root):
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit) or not re.fullmatch(r"[0-9a-f]{40,64}", tree):
        raise DriverError("source_identity")
    names = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    digest = hashlib.sha256()
    total = 0
    for encoded in sorted(set(name for name in names if name)):
        name = encoded.decode("utf-8")
        path = safe_path(root, name)
        if not path.exists():
            digest.update(encoded + b"\0deleted\0")
            continue
        raw = read_regular(path, 32 << 20)
        total += len(raw)
        if total > 512 << 20:
            raise DriverError("source_budget")
        executable = str(bool(path.stat().st_mode & 0o111)).encode()
        digest.update(encoded + b"\0" + executable + b"\0" + hashlib.sha256(raw).digest())
    return {"commit": commit, "tree": tree, "worktree_clean": not git(root, "status", "--porcelain=v1", "--untracked-files=all").strip(), "content_sha256": digest.hexdigest()}


def child_environment():
    # Build-cache locations and the selected toolchain are useful; credentials,
    # provider settings and application/live-service configuration are not.
    keep = ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT", "LANG", "LC_ALL")
    environment = {key: os.environ[key] for key in keep if key in os.environ}
    environment.update(GOTOOLCHAIN="local", GOWORK="off", GOMAXPROCS="1", GOMEMLIMIT="512MiB", GOGC="50", GOFLAGS="-p=1 -mod=readonly")
    return environment


def stop_child(child):
    # A separate owned process group permits cleanup, but every foreground
    # child is synchronously waited; no campaign is detached or backgrounded.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # The leader may have exited while a grandchild ignored SIGTERM.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=5)


def execute(root, command, directory, label, deadline):
    output, error = directory / (label + ".jsonl"), directory / (label + ".stderr")
    with output.open("xb") as stdout, error.open("xb") as stderr:
        child = subprocess.Popen(command, cwd=root, env=child_environment(), stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    raise DriverError("command_timeout")
                if output.stat().st_size + error.stat().st_size > MAX_LOG:
                    raise DriverError("event_budget")
                time.sleep(0.05)
            code = child.wait()
        finally:
            stop_child(child)
    if output.stat().st_size + error.stat().st_size > MAX_LOG:
        raise DriverError("event_budget")
    return code, output


def events(path):
    with path.open("rb") as stream:
        while line := stream.readline(MAX_LINE + 1):
            if len(line) > MAX_LINE:
                raise DriverError("event_line_budget")
            try:
                event = json.loads(line, object_pairs_hook=unique_object)
            except (ValueError, UnicodeError):
                raise DriverError("malformed_events") from None
            if not isinstance(event, dict) or not isinstance(event.get("Action"), str) or not isinstance(event.get("Package"), str):
                raise DriverError("malformed_events")
            if any(key in event and not isinstance(event[key], str) for key in ("Test", "Output")):
                raise DriverError("malformed_events")
            yield event


def inventory(path, expected):
    discovered = Counter()
    packages = {package for package, _name in expected}
    no_tests = set()
    for event in events(path):
        package = event["Package"]
        if event["Action"] == "fail":
            raise DriverError("inventory_failed")
        if event["Action"] == "skip" and (package in packages or package not in no_tests or event.get("Test")):
            raise DriverError("inventory_failed")
        if event["Action"] == "output":
            text = event.get("Output", "").strip()
            if re.fullmatch(r"\?\s+" + re.escape(package) + r"\s+\[no test files\]", text):
                no_tests.add(package)
            if re.fullmatch(r"Fuzz[A-Z0-9_][A-Za-z0-9_]*", text):
                discovered[(event["Package"], text)] += 1
    if set(discovered) != expected or any(count != 1 for count in discovered.values()):
        raise DriverError("inventory_mismatch")


def assessment(path, package, targets, campaign):
    runs, passes, seeds = Counter(), Counter(), Counter()
    seed_runs, seed_passes = Counter(), Counter()
    phase, executions = {}, Counter()
    package_passes = 0
    for event in events(path):
        if event["Package"] != package or event["Action"] in ("skip", "fail"):
            raise DriverError("failed_or_skipped_events")
        name = event.get("Test", "")
        if not name:
            package_passes += event["Action"] == "pass"
            continue
        top = name.split("/", 1)[0]
        if top not in targets:
            raise DriverError("unexpected_target")
        if name != top:
            seed_runs[name] += event["Action"] == "run"
            seed_passes[name] += event["Action"] == "pass"
            if event["Action"] == "pass":
                seeds[top] += 1
        else:
            runs[top] += event["Action"] == "run"
            passes[top] += event["Action"] == "pass"
        if campaign and event["Action"] == "output":
            text = event.get("Output", "")
            match = re.search(r"gathering baseline coverage: ([0-9]+)/([0-9]+) completed, now fuzzing with ([0-9]+) workers", text)
            if match:
                completed, total, workers = map(int, match.groups())
                if completed != total or total < 1 or workers != 1:
                    raise DriverError("invalid_campaign_phase")
                phase[top] = total
            match = re.search(r"execs: ([0-9]+)", text)
            if match:
                executions[top] = max(executions[top], int(match.group(1)))
    if package_passes != 1 or any(runs[t] != 1 or passes[t] != 1 for t in targets):
        raise DriverError("incomplete_target_evidence")
    if campaign:
        if any(t not in phase or executions[t] <= phase[t] for t in targets):
            raise DriverError("unexecuted_campaign")
    elif any(seeds[t] < 1 for t in targets) or set(seed_runs) != set(seed_passes) or any(seed_runs[n] != 1 or seed_passes[n] != 1 for n in seed_runs):
        raise DriverError("incomplete_seed_evidence")
    return {t: {"seeds": seeds[t] if not campaign else phase[t], "executions": executions[t]} for t in targets}


def corpus(root, target):
    relative = target["package"][2:] + "/testdata/fuzz/" + target["name"]
    directory = safe_path(root, relative)
    if not directory.exists():
        return {}
    if not directory.is_dir():
        raise DriverError("invalid_corpus")
    result = {}
    for path in directory.iterdir():
        if len(result) >= 128:
            raise DriverError("corpus_budget")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", path.name):
            raise DriverError("invalid_corpus")
        raw = read_regular(safe_path(root, relative + "/" + path.name), MAX_CRASH)
        if not raw.startswith(b"go test fuzz v1\n"):
            raise DriverError("invalid_corpus")
        result[path.name] = (hashlib.sha256(raw).hexdigest(), raw)
    return result


def retain_crashes(root, target, before, public, summary):
    after = corpus(root, target)
    for name, (digest, raw) in after.items():
        if name in before and before[name][0] == digest:
            continue
        if not re.fullmatch(r"[0-9a-f]{16,64}", name) or summary["crash_count"] >= MAX_CRASHES:
            raise DriverError("crash_artifact_budget")
        directory = public / "crashes" / target["package"][2:] / target["name"]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / digest
        with path.open("xb") as stream:
            stream.write(raw)
        summary["crash_count"] += 1
        summary["crashes"].append({"package": target["package"], "name": target["name"], "sha256": digest, "bytes": len(raw), "path": str(path.relative_to(public))})


def main():
    parser = Parser()
    parser.add_argument("mode", choices=("smoke", "campaign"))
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--seconds", type=number, default=3)
    parser.add_argument("--timeout", type=number, default=600)
    parser.add_argument("--budget", type=number, default=1800)
    summary, public = None, None
    handlers = {}
    try:
        args = parser.parse_args()
        if not 1 <= args.seconds <= 60 or not 1 <= args.timeout <= 1200 or not 1 <= args.budget <= 2700:
            raise DriverError("invalid_settings")
        go = shutil.which(args.go)
        if go is None:
            raise DriverError("missing_go")
        targets = registry(ROOT)
        for target in targets:
            corpus(ROOT, target)
        output = safe_path(ROOT, "tmp/fuzz")
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = output / (args.mode + "-" + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        public, private = directory / "public", directory / "private"
        public.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        summary = {"schema": "evydence-fuzz-run.v1", "status": "failed", "mode": args.mode, "workers": 1, "seconds": args.seconds if args.mode == "campaign" else 0, "started_at": timestamp(), "targets": [dict(t, status="pending", seeds=0, executions=0) for t in targets], "crash_count": 0, "crashes": [], "artifact_policy": "synthetic-public-v1", "limitations": "Finite regression evidence, not exhaustive attack coverage or cryptographic assurance. Raw event logs stay private to the local run."}
        summary["source"] = source_identity(ROOT)
        summary["limits"] = {"command_seconds": args.timeout, "total_seconds": args.budget,
                             "go_memory_soft_limit": "512MiB", "package_parallelism": 1,
                             "log_bytes_per_command": MAX_LOG, "event_line_bytes": MAX_LINE,
                             "crash_bytes_each": MAX_CRASH, "crash_count": MAX_CRASHES}
        end = time.monotonic() + args.budget

        def interrupted(_signal, _frame):
            raise KeyboardInterrupt

        handlers = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

        def invoke(arguments, label):
            return execute(ROOT, [go, *arguments], private, label, min(end, time.monotonic() + args.timeout))

        code, version_file = invoke(["version"], "version")
        version = read_regular(version_file, 256).decode().strip()
        if code or not re.fullmatch(r"go version go[0-9]+\.[0-9]+(?:\.[0-9]+)? [a-z0-9]+/[a-z0-9]+", version):
            raise DriverError("go_identity")
        summary["go_version"] = version
        code, listing = invoke(["test", "-json", "-p=1", "-list", "^Fuzz", "./..."], "inventory")
        if code:
            raise DriverError("inventory_exit")
        expected = {(MODULE + "/" + t["package"][2:], t["name"]) for t in targets}
        inventory(listing, expected)
        groups = [[t] for t in targets] if args.mode == "campaign" else [[t for t in targets if t["package"] == package] for package in sorted({t["package"] for t in targets})]
        for index, group in enumerate(groups):
            package = group[0]["package"]
            before = {t["name"]: corpus(ROOT, t) for t in group}
            names = [t["name"] for t in group]
            arguments = ["test", "-json", "-p=1", "-parallel=1", "-count=1", "-timeout=" + str(args.timeout) + "s"]
            if args.mode == "campaign":
                arguments += ["-run", "^$", "-fuzz", "^" + names[0] + "$", "-fuzztime=" + str(args.seconds) + "s"]
            else:
                arguments += ["-run", "^(" + "|".join(names) + ")$"]
            try:
                code, log = invoke([*arguments, package], "target-" + str(index))
            finally:
                for target in group:
                    retain_crashes(ROOT, target, before[target["name"]], public, summary)
            if code:
                raise DriverError("target_exit")
            results = assessment(log, MODULE + "/" + package[2:], names, args.mode == "campaign")
            for row in summary["targets"]:
                if row["package"] == package and row["name"] in results:
                    row.update(status="passed", **results[row["name"]])
        summary["source_after"] = source_identity(ROOT)
        if summary["source"] != summary["source_after"] or any(row["status"] != "passed" for row in summary["targets"]):
            raise DriverError("source_changed_or_incomplete")
        summary["status"] = "passed"
        print("fuzz-driver: " + args.mode + " passed " + str(len(targets)) + " registered targets serially")
        return 0
    except KeyboardInterrupt:
        if summary is not None:
            summary["error"] = "interrupted"
        return 130
    except (DriverError, OSError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, DriverError) else "driver_io_or_protocol_error"
        if summary is not None:
            summary["error"] = code
        print("fuzz-driver: " + code, file=sys.stderr)
        return 1
    finally:
        if summary is not None:
            summary["finished_at"] = timestamp()
            summary["completed_targets"] = sum(row["status"] == "passed" for row in summary["targets"])
            with (public / "summary.json").open("x") as stream:
                json.dump(summary, stream, indent=2, sort_keys=True)
                stream.write("\n")
        for signal_number, handler in handlers.items():
            signal.signal(signal_number, handler)


if __name__ == "__main__":
    sys.exit(main())
