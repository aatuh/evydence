#!/usr/bin/env python3
"""Check source import direction and flag oversized architecture surfaces."""

from __future__ import annotations

import argparse
from collections import deque
import json
import os
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = "github.com/aatuh/evydence"
CONTEXTS = frozenset({"identity", "release", "evidence", "risk", "package", "verification", "operations", "integration", "experimental"})
MAX_FILE_LINES = 800
MAX_INTERFACE_MEMBERS = 12
OUTWARD_LIBRARIES = (
    "net/http", "database/sql", "github.com/jackc/pgx", "github.com/minio/minio-go",
    "github.com/aws/aws-sdk-go", "github.com/aws/aws-sdk-go-v2",
    "github.com/Azure/azure-sdk-for-go", "cloud.google.com/go",
    "github.com/aatuh/api-toolkit",
)


def within(value: str, prefix: str) -> bool:
    return value == prefix or value.startswith(prefix + "/")


def local(package: str) -> str:
    return package.removeprefix(MODULE + "/")


def layer(package: str) -> tuple[str, str | None]:
    name = local(package)
    parts = name.split("/")
    if len(parts) >= 3 and parts[0] == "internal" and parts[1] in CONTEXTS and parts[2] in {"domain", "app", "query"}:
        return parts[2], parts[1]
    if within(name, "internal/application"):
        return "application", None
    if within(name, "internal/app"):
        return "legacy-application", None
    if within(name, "internal/domain"):
        return "compatibility-domain", None
    return "", None


def outward(package: str) -> bool:
    return within(local(package), "internal/adapters") or within(local(package), "internal/platform/wiring") or within(local(package), "cmd") or any(within(package, prefix) for prefix in OUTWARD_LIBRARIES)


def dependency_error(package: str, target: str) -> str | None:
    role, context = layer(package)
    target_role, target_context = layer(target)
    if not role:
        return None
    if outward(target):
        return "core cannot import adapter/runtime"
    if role == "domain" and ("." in target.split("/")[0] or target == "C"):
        return "context domain must be independent of"
    if role in {"app", "query"}:
        if target_role in {"app", "query"} and target_context != context:
            return "foreign context service dependency; use a scoped port, read model or event instead of"
        if context != "experimental" and target_context == "experimental":
            return "production context cannot depend on experimental context"
        if within(local(target), "internal/app") and not within(local(target), "internal/app/query"):
            return "context service cannot depend on legacy application"
    if role in {"compatibility-domain", "application"} and target_role in {"app", "query", "legacy-application"}:
        return "shared domain/application cannot depend on context or legacy service"
    return None


def path_to_forbidden(start: str, graph: dict[str, set[str]]) -> list[str] | None:
    pending = deque([[start]])
    seen = {start}
    while pending:
        route = pending.popleft()
        for target in sorted(graph.get(route[-1], ())):
            if dependency_error(start, target):
                return route + [target]
            if target not in seen:
                seen.add(target)
                pending.append(route + [target])
    return None


def import_cycles(graph: dict[str, set[str]]) -> list[str]:
    active: list[str] = []
    visited: set[str] = set()
    cycles: set[str] = set()

    def visit(package: str) -> None:
        if package in active:
            loop = active[active.index(package):]
            smallest = loop.index(min(loop))
            loop = loop[smallest:] + loop[:smallest]
            cycles.add("import cycle: " + " -> ".join(map(local, loop + [loop[0]])))
            return
        if package in visited:
            return
        active.append(package)
        for target in sorted(graph.get(package, ())):
            if target in graph:
                visit(target)
        active.pop()
        visited.add(package)

    for package in sorted(graph):
        visit(package)
    return sorted(cycles)


def analyze(files: list[dict]) -> tuple[list[str], list[str]]:
    errors: set[str] = set()
    warnings: set[str] = set()
    graph: dict[str, set[str]] = {}
    for file in files:
        package = file["package"]
        graph.setdefault(package, set()).update(item["path"] for item in file["imports"])
        for item in file["imports"]:
            target = item["path"]
            violation = dependency_error(package, target)
            if violation:
                errors.add(f'{file["path"]}: {violation} {local(target)}')
        if file["generated"]:
            continue  # Generated declarations are exempt from review size, not import rules.
        if file["lines"] > MAX_FILE_LINES:
            warnings.add(f'{file["path"]}: review file size {file["lines"]} > {MAX_FILE_LINES} lines')
        for interface in file["interfaces"]:
            members = interface["methods"] + interface["embeddings"]
            if members > MAX_INTERFACE_MEMBERS:
                warnings.add(f'{file["path"]}: review public interface {interface["name"]}: {members} declared methods/embeddings > {MAX_INTERFACE_MEMBERS}')
    for package in sorted(graph):
        if layer(package)[0]:
            route = path_to_forbidden(package, graph)
            if route and len(route) > 2:
                errors.add("core reaches forbidden dependency: " + " -> ".join(map(local, route)))
    errors.update(import_cycles(graph))
    return sorted(errors), sorted(warnings)


def inspect_sources(root: pathlib.Path) -> list[dict]:
    # The trusted checkout supplies the inspector. The selected tree is parsed,
    # not passed as a Go build/run target. No shell interpolation is used.
    result = subprocess.run(
        [os.environ.get("GO", "go"), "run", "./cmd/architecture-inspect", "-root", str(root), "-module", MODULE],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode:
        raise ValueError("source inspection failed: " + result.stderr.strip())
    inventory = json.loads(result.stdout)
    if inventory.get("version") != 1 or not isinstance(inventory.get("files"), list) or not inventory["files"]:
        raise ValueError("source inspection produced an empty or unsupported inventory")
    return inventory["files"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="source root to inspect, never execute")
    args = parser.parse_args()
    try:
        files = inspect_sources(args.root.resolve())
        errors, warnings = analyze(files)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"architecture-check: {error}", file=sys.stderr)
        return 1
    for warning in warnings:
        print("architecture-check: " + warning, file=sys.stderr)
    for error in errors:
        print("architecture-check: " + error, file=sys.stderr)
    if errors:
        print(f"architecture-check: failed ({len(errors)} violations; {len(warnings)} review flags)", file=sys.stderr)
        return 1
    print(f"architecture-check: passed ({len(files)} source files; {len(warnings)} review flags)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
