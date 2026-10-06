#!/usr/bin/env python3
"""Keep complete live test gates bounded without exhausting Go's 10m default."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class GateWatchdogTests(unittest.TestCase):
    def test_complete_package_runs_have_explicit_watchdogs(self):
        targets = {
            "Makefile": [
                "$(GO) test ./... -timeout=30m",
                "$(GO) test ./... -race -count=1 -timeout=30m",
                "$(GO) test ./... -coverprofile=coverage.out -timeout=30m",
                "$(GO) test ./internal/adapters/postgres ./internal/app -count=1 -timeout=30m",
            ],
            "scripts/integration_check.sh": [
                "go test ./internal/adapters/postgres -count=1 -timeout=30m",
            ],
            "scripts/coverage_check.sh": [
                'go test ./... -coverprofile="$profile" -timeout=30m',
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


if __name__ == "__main__":
    unittest.main()
