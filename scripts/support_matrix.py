#!/usr/bin/env python3
"""Validate support policy and build drift; emit data, not qualification proof."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_POLICY_BYTES = 64 * 1024
GO_TOOLS = ("golangci_lint", "gosec", "govulncheck")
ARCHIVE_TOOLS = ("helm", "oasdiff")
TARGETS = frozenset(("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"))
# Extending runtime/server claims requires an explicit qualification change.
RUNTIME_TARGETS = frozenset(("linux/amd64",))
SERVER_COMMANDS = frozenset(("evydence-api", "evydence-worker", "evydence-migrate"))
COMPONENT = r"(?:0|[1-9][0-9]{0,2})"
VERSION = rf"{COMPONENT}\.{COMPONENT}\.{COMPONENT}"


class PolicyError(ValueError):
    def __init__(self):
        super().__init__("invalid support policy")


def require(condition):
    if not condition:
        raise PolicyError()


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def pinned_version(value, prefix=""):
    require(type(value) is str and re.fullmatch(re.escape(prefix) + VERSION, value) is not None)


def target_list(value, allowed):
    require(type(value) is list and 0 < len(value) <= len(allowed))
    require(all(type(item) is str and item in allowed for item in value))
    require(len(value) == len(set(value)))


def parse_policy(raw):
    require(type(raw) is bytes and len(raw) <= MAX_POLICY_BYTES)
    try:
        def invalid_constant(_value):
            raise PolicyError()
        policy = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise PolicyError() from None
    keys(policy, ("schema_version", "go", "tools", "release", "sdk"))
    require(policy["schema_version"] == "evydence-support-policy.v1")
    go = policy["go"]
    keys(go, ("minimum", "current"))
    for value in go.values():
        pinned_version(value)
        require(value.startswith("1."))
    require(tuple(map(int, go["minimum"].split("."))) <= tuple(map(int, go["current"].split("."))))
    tools = policy["tools"]
    keys(tools, GO_TOOLS + ARCHIVE_TOOLS)
    for name in GO_TOOLS:
        keys(tools[name], ("version",))
        pinned_version(tools[name]["version"], "v")
    for name in ARCHIVE_TOOLS:
        keys(tools[name], ("version", "linux_amd64_sha256"))
        pinned_version(tools[name]["version"], "v" if name == "helm" else "")
        digest = tools[name]["linux_amd64_sha256"]
        require(type(digest) is str and re.fullmatch(r"[a-f0-9]{64}", digest) is not None)
    release = policy["release"]
    keys(release, ("cli_targets", "runtime_targets", "server_targets", "server_commands", "cli_command"))
    target_list(release["cli_targets"], TARGETS)
    target_list(release["runtime_targets"], RUNTIME_TARGETS)
    target_list(release["server_targets"], RUNTIME_TARGETS)
    require(set(release["runtime_targets"]) <= set(release["cli_targets"]))
    require(set(release["server_targets"]) <= set(release["runtime_targets"]))
    target_list(release["server_commands"], SERVER_COMMANDS)
    require(set(release["server_commands"]) == SERVER_COMMANDS and release["cli_command"] == "evydence")
    keys(policy["sdk"], ("go", "python", "typescript"))
    require(all(value == "source-wrapper" for value in policy["sdk"].values()))
    return policy


def load_policy(root=ROOT):
    path = Path(root) / "release/support-matrix.json"
    descriptor = None
    try:
        require(stat.S_ISREG(path.lstat().st_mode))
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream:
            return parse_policy(stream.read(MAX_POLICY_BYTES + 1))
    except (OSError, ValueError):
        raise PolicyError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def go_versions(policy):
    return list(dict.fromkeys((policy["go"]["minimum"], policy["go"]["current"])))


def release_plan(policy):
    """Return declared commands/qualification targets, never test receipts."""
    release = policy["release"]
    plan = []
    for target in release["cli_targets"]:
        commands = [release["cli_command"]]
        if target in release["server_targets"]:
            commands.extend(release["server_commands"])
        goos, goarch = target.split("/")
        plan.append({"target": target, "goos": goos, "goarch": goarch,
                     "commands": commands, "runtime_target": target in release["runtime_targets"]})
    return plan


class ArgumentError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ArgumentError()


def main(argv=None, *, root=ROOT, stdout=None, stderr=None):
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    parser = Parser(prog="support_matrix", description=__doc__)
    group = parser.add_mutually_exclusive_group()
    for flag in ("validate", "check", "render", "go-minimum", "go-current", "go-versions", "release-plan"):
        group.add_argument("--" + flag, action="store_true")
    group.add_argument("--tool-version", choices=GO_TOOLS + ARCHIVE_TOOLS)
    group.add_argument("--tool-sha256", choices=ARCHIVE_TOOLS)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            args = parser.parse_args(argv)
    except ArgumentError:
        stderr.write("support policy: invalid arguments\n")
        return 2
    except SystemExit as result:
        return 0 if result.code == 0 else 2
    try:
        policy = load_policy(root)
        if args.check:
            from support_matrix_artifacts import check_artifacts
            failures = check_artifacts(policy, root=root)
            if failures:
                stderr.write("\n".join("support matrix: " + item for item in failures) + "\n")
                return 1
            result = "support matrix artifacts are current"
        elif args.render:
            from support_matrix_artifacts import render_matrix
            result = render_matrix(policy)
        elif args.go_minimum:
            result = policy["go"]["minimum"]
        elif args.go_current:
            result = policy["go"]["current"]
        elif args.go_versions:
            result = json.dumps(go_versions(policy))
        elif args.release_plan:
            result = json.dumps(release_plan(policy))
        elif args.tool_version:
            result = policy["tools"][args.tool_version]["version"]
        elif args.tool_sha256:
            result = policy["tools"][args.tool_sha256]["linux_amd64_sha256"]
        else:
            result = "support policy is valid"
        stdout.write(result + "\n")
        return 0
    except PolicyError:
        stderr.write("support policy: invalid declaration\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
