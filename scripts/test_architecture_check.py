#!/usr/bin/env python3
"""Regressions for the EVY-906 import graph and review thresholds."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest

import architecture_check as check


def source(package: str, imports: tuple[str, ...] = (), **extra: object) -> dict:
    return {
        "path": package + "/source.go",
        "package": check.MODULE + "/" + package,
        "imports": [{"path": item} for item in imports],
        "interfaces": [],
        "generated": False,
        "lines": 20,
        **extra,
    }


class ArchitectureCheckTests(unittest.TestCase):
    def test_core_cannot_import_adapters_even_in_generated_source(self) -> None:
        for package in ("internal/application", "internal/app", "internal/release/app", "internal/evidence/query", "internal/risk/domain"):
            with self.subTest(package=package):
                errors, _ = check.analyze([source(package, (check.MODULE + "/internal/adapters/postgres",), generated=True)])
                self.assertTrue(errors)
                self.assertIn("adapter", "\n".join(errors))

    def test_domain_is_inward_and_application_cannot_call_foreign_service(self) -> None:
        for package, target in (
            ("internal/risk/domain", "internal/risk/app"),
            ("internal/release/app", "internal/evidence/app"),
            ("internal/package/query", "internal/risk/app"),
            ("internal/identity/app", "internal/experimental/query"),
            ("internal/application", "internal/risk/app"),
            ("internal/package/query", "internal/experimental/domain"),
        ):
            with self.subTest(package=package, target=target):
                errors, _ = check.analyze([source(package, (check.MODULE + "/" + target,))])
                self.assertTrue(errors)

    def test_ports_models_and_inward_adapter_dependencies_are_allowed(self) -> None:
        errors, warnings = check.analyze([
            source("internal/release/app", ("context", check.MODULE + "/internal/application", check.MODULE + "/internal/release/domain", check.MODULE + "/internal/identity/domain")),
            source("internal/package/query", (check.MODULE + "/internal/risk/domain", check.MODULE + "/internal/package/app")),
            source("internal/adapters/postgres", (check.MODULE + "/internal/release/app",)),
            source("cmd/evydence-api", (check.MODULE + "/internal/adapters/postgres",)),
        ])
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_core_cannot_reach_an_adapter_through_an_innocent_helper(self) -> None:
        errors, _ = check.analyze([
            source("internal/release/app", (check.MODULE + "/internal/platform/helper",)),
            source("internal/platform/helper", (check.MODULE + "/internal/adapters/postgres",)),
        ])
        self.assertIn("internal/release/app -> internal/platform/helper -> internal/adapters/postgres", "\n".join(errors))

    def test_foreign_service_direction_cannot_be_hidden_in_a_helper(self) -> None:
        errors, _ = check.analyze([
            source("internal/package/query", (check.MODULE + "/internal/platform/helper",)),
            source("internal/platform/helper", (check.MODULE + "/internal/risk/app",)),
        ])
        self.assertIn("internal/package/query -> internal/platform/helper -> internal/risk/app", "\n".join(errors))

    def test_external_transport_and_storage_libraries_are_not_core_ports(self) -> None:
        for target in ("net/http", "database/sql", "github.com/jackc/pgx/v5", "github.com/minio/minio-go/v7", "github.com/aatuh/api-toolkit/v3/httpx"):
            with self.subTest(target=target):
                errors, _ = check.analyze([source("internal/release/app", (target,))])
                self.assertTrue(errors)

    def test_import_cycles_are_reported_deterministically(self) -> None:
        files = [
            source("internal/a", (check.MODULE + "/internal/b",)),
            source("internal/b", (check.MODULE + "/internal/a",)),
        ]
        errors, _ = check.analyze(files)
        reversed_errors, _ = check.analyze(list(reversed(files)))
        self.assertEqual(errors, reversed_errors)
        self.assertIn("import cycle", "\n".join(errors))

    def test_review_limits_flag_large_files_and_public_interface_embeddings(self) -> None:
        files = [source("internal/release/app", lines=check.MAX_FILE_LINES + 1, interfaces=[
            {"name": "Broad", "methods": check.MAX_INTERFACE_MEMBERS, "embeddings": 1},
        ])]
        errors, warnings = check.analyze(files)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 2)
        self.assertIn("Broad", "\n".join(warnings))
        files[0]["generated"] = True
        self.assertEqual(check.analyze(files), ([], []))

    def test_limits_are_inclusive_and_not_a_generated_import_exemption(self) -> None:
        errors, warnings = check.analyze([source("internal/release/app", lines=check.MAX_FILE_LINES, interfaces=[
            {"name": "Focused", "methods": check.MAX_INTERFACE_MEMBERS, "embeddings": 0},
        ])])
        self.assertEqual((errors, warnings), ([], []))

    def test_deliberate_boundary_violation_is_found_through_real_go_syntax(self) -> None:
        with tempfile.TemporaryDirectory(prefix="architecture-fixture-") as directory:
            root = pathlib.Path(directory)
            package = root / "internal/release/app"
            package.mkdir(parents=True)
            (package / "source.go").write_text(
                'package app\nimport database "\\x67ithub.com/aatuh/evydence/internal/adapters/postgres"\n'
                'func init(){panic("fixture must not execute")}\n', encoding="utf-8"
            )
            result = subprocess.run(
                ["python3", str(check.ROOT / "scripts/architecture_check.py"), "--root", str(root)],
                cwd=check.ROOT, capture_output=True, text=True, check=False, timeout=60,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("internal/release/app/source.go", result.stderr)
            self.assertIn("adapter", result.stderr)
            self.assertNotIn("fixture must not execute", result.stderr)


if __name__ == "__main__":
    unittest.main()
