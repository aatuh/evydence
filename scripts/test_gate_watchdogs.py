#!/usr/bin/env python3
"""Keep complete live test gates bounded without exhausting Go's 10m default."""
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class GateWatchdogTests(unittest.TestCase):
    def test_complete_package_runs_have_explicit_watchdogs(self):
        targets = {
            "Makefile": [
                "$(GO) test ./... -timeout=30m",
                "$(GO) test ./... -race -count=1 -timeout=30m",
                "$(GO) test ./... -coverpkg=./... -coverprofile=coverage.out -timeout=30m",
                "$(GO) test ./internal/adapters/postgres ./internal/app -count=1 -timeout=30m",
            ],
            "scripts/integration_check.sh": [
                "go test ./internal/adapters/postgres -count=1 -timeout=30m",
            ],
            "scripts/coverage_check.sh": [
                'go test ./... -coverpkg=./... -coverprofile="$profile" -timeout=30m',
            ],
        }
        for path, commands in targets.items():
            source = (ROOT / path).read_text(encoding="utf-8")
            for command in commands:
                with self.subTest(path=path, command=command):
                    self.assertTrue(command in source, f"{path} must retain: {command}")

    def test_coverage_still_uses_one_unfiltered_profile(self):
        source = (ROOT / "scripts/coverage_check.sh").read_text(encoding="utf-8")
        self.assertEqual(source.count("go test "), 1)
        self.assertIn('EVYDENCE_COVERAGE_THRESHOLD:-80.0', source)
        self.assertIn('EVYDENCE_CRITICAL_COVERAGE_THRESHOLD:-81.0', source)
        self.assertNotIn("-skip", source)
        self.assertNotIn("-run", source)

    def test_production_gate_serializes_packages_not_test_concurrency(self):
        source = (ROOT / "scripts/production_check.sh").read_text(encoding="utf-8")
        setting = 'export GOFLAGS="${GOFLAGS:+$GOFLAGS }-p=1"'
        self.assertTrue(setting in source, "production gate must bound shared-database package concurrency")
        self.assertLess(source.index(setting), source.index("make integration-check"))
        self.assertNotIn("GOMAXPROCS=", source)
        self.assertNotIn("-parallel", source)
        self.assertNotIn("-run", source)
        self.assertNotIn("-skip", source)
        for previous in (None, "", "-mod=readonly", "-mod=readonly -p=8", "$(printf unexpected)"):
            with self.subTest(previous=previous):
                environment = dict(os.environ)
                environment.pop("GOFLAGS", None)
                if previous is not None:
                    environment["GOFLAGS"] = previous
                result = subprocess.run(
                    ["sh", "-eu", "-c", setting + '\nprintf "%s" "$GOFLAGS"'],
                    env=environment, capture_output=True, text=True, timeout=5, check=True,
                )
                self.assertEqual(result.stdout, (previous + " " if previous else "") + "-p=1")


if __name__ == "__main__":
    unittest.main()
