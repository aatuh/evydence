#!/usr/bin/env python3
"""Check operator input and artifact preservation before the binary harness runs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent


class RuntimeLifecycleGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "tmp").mkdir()
        (self.root / "bin").mkdir()
        for name in ("runtime_lifecycle_check.sh", "runtime_lifecycle_evidence.py"):
            shutil.copy(SOURCE / name, self.root / "scripts" / name)
        go = self.root / "bin/go"
        go.write_text("""#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
Path('invocation.json').write_text(json.dumps({'args':sys.argv[1:],'api':os.environ['EVYDENCE_LIFECYCLE_API_BIN'],'worker':os.environ['EVYDENCE_LIFECYCLE_WORKER_BIN']}))
raise SystemExit(1)
""")
        go.chmod(0o755)
        for name in ("api", "worker"):
            binary = self.root / "bin" / name
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"],
            EVYDENCE_TEST_DATABASE_URL="postgres://private-canary@example.invalid/test",
            EVYDENCE_LIFECYCLE_API_BIN="bin/api", EVYDENCE_LIFECYCLE_WORKER_BIN="bin/worker",
            EVYDENCE_LIFECYCLE_EXPECTED_COMMIT="fixture", EVYDENCE_LIFECYCLE_ARTIFACT_DIR="tmp/evidence")

    def run_gate(self, **changes):
        return subprocess.run(["sh", "scripts/runtime_lifecycle_check.sh"], cwd=self.root,
                              env=dict(self.env, **changes), capture_output=True, text=True, timeout=10)

    def test_required_database_and_binaries_fail_before_go(self):
        for changes in ({"EVYDENCE_TEST_DATABASE_URL": ""}, {"EVYDENCE_LIFECYCLE_API_BIN": ""},
                        {"EVYDENCE_LIFECYCLE_WORKER_BIN": "missing"}):
            with self.subTest(changes=list(changes)):
                result = self.run_gate(**changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "invocation.json").exists())
                self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_escaping_or_existing_artifacts_are_preserved(self):
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "keep"
        marker.write_text("preserved")
        (self.root / "tmp/evidence").symlink_to(outside, target_is_directory=True)
        for path in ("../outside", "tmp/../outside", "tmp/evidence"):
            result = self.run_gate(EVYDENCE_LIFECYCLE_ARTIFACT_DIR=path)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "invocation.json").exists())
            self.assertEqual(marker.read_text(), "preserved")

    def test_relative_binary_paths_are_resolved_before_go_changes_directory(self):
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)  # The fake Go command fails deliberately.
        invocation = json.loads((self.root / "invocation.json").read_text())
        self.assertEqual(invocation["api"], str(self.root / "bin/api"))
        self.assertEqual(invocation["worker"], str(self.root / "bin/worker"))
        for required in ("-tags=releasebinary", "-json", "-count=1", "-timeout=3m"):
            self.assertIn(required, invocation["args"])

    def test_symlinked_parent_cannot_redirect_new_artifacts(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "tmp/linked").symlink_to(outside, target_is_directory=True)
        result = self.run_gate(EVYDENCE_LIFECYCLE_ARTIFACT_DIR="tmp/linked/new-evidence")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "invocation.json").exists())
        self.assertFalse((outside / "new-evidence").exists())

    def test_release_artifact_gate_requires_lifecycle_results_before_summary(self):
        source = (SOURCE / "black_box_release_artifact_check.sh").read_text()
        invocation = source.index("sh scripts/runtime_lifecycle_check.sh")
        self.assertLess(invocation, source.index("summary = {"))
        self.assertIn('EVYDENCE_LIFECYCLE_API_BIN="$release_dir/evydence-api"', source)
        self.assertIn('EVYDENCE_LIFECYCLE_WORKER_BIN="$release_dir/evydence-worker"', source)
        self.assertIn('lifecycle["status"] != "passed"', source)


if __name__ == "__main__":
    unittest.main()
