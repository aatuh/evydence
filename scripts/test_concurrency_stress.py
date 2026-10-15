#!/usr/bin/env python3
"""Exercise the stress gate's process and evidence contract without Go builds."""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyStressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("concurrency_stress.sh", "concurrency_stress.py"):
            source = ROOT / "scripts" / name
            if source.exists():
                shutil.copyfile(source, scripts / name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = self.bin / "go"
        fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
pathlib.Path("invocation.json").write_text(json.dumps(sys.argv[1:]))
args=sys.argv[1:]
names=next(v for v in args if v.startswith("^(")).removeprefix("^(").removesuffix(")$").split("|")
count=int(next(v.split("=",1)[1] for v in args if v.startswith("-count=")))
mode=os.getenv("FAKE_MODE", "pass")
if mode=="block":
    import signal
    pathlib.Path("child.pid").write_text(str(os.getpid()))
    signal.pause()
for package in [p for p in args if p.startswith("./internal/")]:
    full="github.com/aatuh/evydence/"+package[2:]
    # Ask the driver's plan which tests belong to this package. The contract
    # below independently checks the real critical selection and source names.
    import runpy
    cases=runpy.run_path("scripts/concurrency_stress.py")["CASES"][package]
    for name in cases:
        for i in range(count*3):
            if mode=="missing" and name==names[0]: continue
            action="skip" if mode=="skip" and name==names[0] else "pass"
            print(json.dumps({"Action":action,"Package":full,"Test":name}))
    print(json.dumps({"Action":"pass","Package":full}))
if mode=="failure": sys.exit(7)
if mode=="malformed": print("not JSON")
''')
        fake.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        EVYDENCE_TEST_DATABASE_URL="postgres://secret-canary@example.invalid/test",
                        EVYDENCE_CONCURRENCY_STRESS_ITERATIONS="2")

    def run_gate(self, **changes):
        env = dict(self.env, **changes)
        return subprocess.run(["sh", "scripts/concurrency_stress.sh"], cwd=self.root,
                              env=env, capture_output=True, text=True, timeout=10)

    def test_requires_live_database_before_starting_go(self):
        result = self.run_gate(EVYDENCE_TEST_DATABASE_URL="")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "invocation.json").exists())

    def test_rejects_invalid_or_excessive_counts_before_starting_go(self):
        for value in ("", "0", "-1", "1;echo injected", "1.5", "1001", "9" * 100):
            with self.subTest(value=value):
                result = self.run_gate(EVYDENCE_CONCURRENCY_STRESS_ITERATIONS=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "invocation.json").exists())

    def test_requires_race_multiple_schedulers_and_complete_pass_evidence(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = json.loads((self.root / "invocation.json").read_text())
        for flag in ("-json", "-race", "-cpu=1,2,4", "-count=2", "-p=1", "-timeout=30m"):
            self.assertIn(flag, args)
        summary = json.loads((self.root / "tmp/concurrency-stress/summary.json").read_text())
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["passes_per_test"], 6)
        self.assertNotIn("secret-canary", result.stdout + result.stderr + json.dumps(summary))

    def test_skipped_missing_failed_and_malformed_runs_cannot_pass(self):
        for mode in ("skip", "missing", "failure", "malformed"):
            with self.subTest(mode=mode):
                result = self.run_gate(FAKE_MODE=mode)
                self.assertNotEqual(result.returncode, 0)
                summary = json.loads((self.root / "tmp/concurrency-stress/summary.json").read_text())
                self.assertEqual(summary["status"], "failed")
                self.assertNotIn("secret-canary", result.stdout + result.stderr + json.dumps(summary))

    def test_evidence_symlink_is_rejected_without_overwriting_its_target(self):
        output = self.root / "tmp/concurrency-stress"
        output.mkdir(parents=True)
        target = self.root / "untouched"
        target.write_text("preserve")
        (output / "events.jsonl").symlink_to(target)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), "preserve")

    def test_termination_stops_owned_child_and_records_failure(self):
        child = subprocess.Popen(["sh", "scripts/concurrency_stress.sh"], cwd=self.root,
                                 env=dict(self.env, FAKE_MODE="block"), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        pid = None
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            pid = int((self.root / "child.pid").read_text())
            child.terminate()
            self.assertNotEqual(child.wait(timeout=5), 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            summary = json.loads((self.root / "tmp/concurrency-stress/summary.json").read_text())
            self.assertEqual(summary["status"], "failed")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            if pid is not None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_selected_cases_exist_and_cover_current_native_boundaries(self):
        spec = importlib.util.spec_from_file_location("stress", ROOT / "scripts/concurrency_stress.py")
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        native = driver.CASES["./internal/platform/wiring"]
        for boundary in ("CatalogCreation", "SigningKey", "CustomerCreation", "SessionReplacement", "WorkerReplicas"):
            self.assertTrue(any(boundary in name for name in native), boundary)
        self.assertIn("TestStoreConcurrentIdempotencyAcrossLedgerInstances", driver.CASES["./internal/adapters/postgres"])
        # Preserve every EVY-303 repeated case while expanding native coverage.
        import re
        old_cases = set(re.findall(r"^func (TestWithIdempotency(?:Concurrent|Canceled|Recovers)\w*)\(",
                                  (ROOT / "internal/app/idempotency_concurrency_test.go").read_text(), re.M))
        self.assertTrue(old_cases.issubset(driver.CASES["./internal/app"]))
        for package, cases in driver.CASES.items():
            source = "\n".join(p.read_text() for p in (ROOT / package).glob("*_test.go"))
            for case in cases:
                self.assertIn("func " + case + "(t *testing.T)", source)

    def test_production_and_unconditional_ci_job_enforce_stress(self):
        self.assertIn("make concurrency-stress-check", (ROOT / "scripts/production_check.sh").read_text())
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("name: Race and Stress", workflow)
        stress = workflow.split("  race-and-stress:", 1)[1]
        self.assertIn("run: make concurrency-stress-check", stress)
        self.assertNotIn("continue-on-error", stress)
        self.assertNotIn("if: github", stress)
        self.assertIn("tmp/concurrency-stress/summary.json", stress)


if __name__ == "__main__":
    unittest.main()
