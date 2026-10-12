#!/usr/bin/env python3
"""Exercise coverage measurement across real Go package boundaries."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = "github.com/aatuh/evydence"


class CoverageMeasurementTests(unittest.TestCase):
    def test_gate_counts_cross_package_calls_and_keeps_unexecuted_code(self):
        with tempfile.TemporaryDirectory(prefix="evydence-coverage-") as directory:
            root = pathlib.Path(directory)
            files = {
                "go.mod": f"module {MODULE}\n\ngo 1.25.0\n",
                "internal/adapters/postgres/repositories/repository.go": (
                    "package repositories\n"
                    "func Selected() int { return 41 }\n"
                    "func Unexecuted() int { return -1 }\n"
                ),
                "cmd/unexecuted/main.go": (
                    "package main\nfunc main() { panic(\"not executed\") }\n"
                ),
                "scripts/coverage_check.sh": (
                    ROOT / "scripts/coverage_check.sh"
                ).read_text(encoding="utf-8"),
            }
            for package in ("internal/platform/wiring", "internal/release/query"):
                files[f"{package}/caller.go"] = (
                    'package caller\nimport "' + MODULE
                    + '/internal/adapters/postgres/repositories"\n'
                    "func Read() int { return repositories.Selected() + 1 }\n"
                )
                files[f"{package}/caller_test.go"] = (
                    'package caller\nimport "testing"\n'
                    "func TestRead(t *testing.T) {\n"
                    ' if got := Read(); got != 42 { t.Fatalf("got %d", got) }\n'
                    "}\n"
                )
            for name, source in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")

            profile = root / "coverage profile; literal.out"
            environment = dict(os.environ)
            environment.update({
                "GOWORK": "off",
                "GOPROXY": "off",
                "GOFLAGS": "-p=1",
                "EVYDENCE_TEST_DATABASE_URL": "measurement-fixture",
                "EVYDENCE_COVERAGE_PROFILE": str(profile),
                # This tiny measurement fixture is not production coverage.
                "EVYDENCE_COVERAGE_THRESHOLD": "1",
                "EVYDENCE_CRITICAL_COVERAGE_THRESHOLD": "1",
            })
            result = subprocess.run(
                ["sh", str(root / "scripts/coverage_check.sh")],
                cwd=root, env=environment, capture_output=True, text=True,
                timeout=90, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows = [line.split() for line in profile.read_text().splitlines()[1:]]
            blocks = {}
            for location, statements, count in rows:
                weight = int(statements)
                previous = blocks.get(location, (weight, False))
                self.assertEqual(previous[0], weight)
                blocks[location] = (weight, previous[1] or int(count) > 0)
            selected = [block for key, block in blocks.items()
                        if "/repository.go:2." in key]
            unexecuted = [block for key, block in blocks.items()
                          if "/repository.go:3." in key]
            command = [block for key, block in blocks.items()
                       if "/cmd/unexecuted/" in key]
            self.assertTrue(selected, "cross-package repository omitted")
            self.assertTrue(all(covered for _, covered in selected),
                            "repository calls from integration packages not measured")
            self.assertTrue(unexecuted, "unexecuted repository code omitted")
            self.assertTrue(command, "package without tests omitted")
            self.assertTrue(all(not covered for _, covered in unexecuted + command),
                            "unexecuted code falsely counted as covered")
            critical = [block for key, block in blocks.items() if key.startswith((
                MODULE + "/internal/platform/",
                MODULE + "/internal/adapters/postgres/",
            ))]
            expected = sum(weight for weight, covered in critical if covered) * 100
            expected /= sum(weight for weight, _ in critical)
            measured = re.search(r"critical-package coverage ([0-9.]+)% meets", result.stdout)
            self.assertIsNotNone(measured, result.stdout)
            self.assertEqual(measured.group(1), f"{expected:.1f}",
                             "shared statement blocks counted more than once")
            self.assertFalse((root / "literal.out").exists())
            for kind, variable in (
                ("total", "EVYDENCE_COVERAGE_THRESHOLD"),
                ("critical-package", "EVYDENCE_CRITICAL_COVERAGE_THRESHOLD"),
            ):
                with self.subTest(floor=kind):
                    failing_environment = dict(environment)
                    failing_environment.pop(variable)
                    failure = subprocess.run(
                        ["sh", str(root / "scripts/coverage_check.sh")],
                        cwd=root, env=failing_environment,
                        capture_output=True, text=True, timeout=90, check=False,
                    )
                    self.assertEqual(failure.returncode, 1, failure.stderr)
                    self.assertIn(f"{kind} coverage", failure.stderr)
                    self.assertIn("below required", failure.stderr)

    def test_gate_retains_complete_scope_and_both_production_floors(self):
        source = (ROOT / "scripts/coverage_check.sh").read_text(encoding="utf-8")
        self.assertEqual(source.count("go test "), 1)
        self.assertIn("go test ./...", source)
        self.assertIn("-coverpkg=./...", source)
        self.assertIn("EVYDENCE_COVERAGE_THRESHOLD:-80.0", source)
        self.assertIn("EVYDENCE_CRITICAL_COVERAGE_THRESHOLD:-81.0", source)
        self.assertIn('if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]', source)
        for forbidden in ("-run", "-skip", "-short", "|| true"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
