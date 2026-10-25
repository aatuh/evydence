#!/usr/bin/env python3
"""Exercise inventory, execution and artifact contracts without Go builds."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FuzzDriverTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "scripts").mkdir()
        source = ROOT / "scripts/fuzz_driver.py"
        if source.exists():
            shutil.copyfile(source, self.root / "scripts/fuzz_driver.py")
        self.registry = {
            "schema": "evydence-fuzz-targets.v1",
            "artifact_policy": "synthetic-public-v1",
            "targets": [
                {"package": "./internal/a", "name": "FuzzOne"},
                {"package": "./internal/a", "name": "FuzzTwo"},
                {"package": "./cmd/example", "name": "FuzzThree"},
            ],
        }
        self.write_registry()
        (self.root / "go.mod").write_text("module github.com/aatuh/evydence\n\ngo 1.26.10\n")
        (self.root / ".gitignore").write_text("tmp/\n")
        for package in ("internal/a", "cmd/example"):
            (self.root / package).mkdir(parents=True)
            (self.root / package / "fuzz_test.go").write_text("package example\n")
        self.fake = self.root / "fake-go"
        self.fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, re, signal, subprocess, sys
root=pathlib.Path.cwd(); out=root/"tmp/fake";out.mkdir(parents=True,exist_ok=True)
args=sys.argv[1:]
with (out/"invocations.jsonl").open("a") as stream: stream.write(json.dumps(args)+"\\n")
(out/"environment.json").write_text(json.dumps(sorted(os.environ)))
if args==["version"]:
 print("go version go1.27.3 linux/amd64");sys.exit(0)
targets=json.loads((root/"scripts/fuzz-targets.json").read_text())["targets"]
mode=(root/"mode").read_text().strip()
def emit(action,package,**extra):
 print(json.dumps(dict(Action=action,Package="github.com/aatuh/evydence/"+package[2:],**extra)),flush=True)
if "-list" in args:
 if mode=="no_test_package":
  emit("output","./internal/no_tests",Output="? github.com/aatuh/evydence/internal/no_tests [no test files]\\n")
  emit("skip","./internal/no_tests")
 for package in sorted({x["package"] for x in targets}):
  emit("start",package)
  for target in targets:
   if target["package"]!=package:continue
   if mode=="missing_discovery" and target==targets[0]:continue
   emit("output",package,Output=target["name"]+"\\n")
  if mode=="extra_discovery" and package==targets[0]["package"]:emit("output",package,Output="FuzzUnregistered\\n")
  emit("pass",package)
  if mode=="skip_discovery" and package==targets[0]["package"]:emit("skip",package)
 sys.exit(0)
package=args[-1]
selected=[x for x in targets if x["package"]==package]
if "-fuzz" in args:
 pattern=args[args.index("-fuzz")+1]
 selected=[x for x in selected if re.fullmatch(pattern,x["name"])]
if mode in ("block","resistant_child"):
 child=subprocess.Popen([sys.executable,"-c","import signal;"+("signal.signal(signal.SIGTERM,signal.SIG_IGN);" if mode=="resistant_child" else "")+"print('ready',flush=True);signal.pause()"],stdout=subprocess.PIPE)
 child.stdout.readline()
 (out/"child.pid").write_text(str(child.pid));(out/"parent.pid").write_text(str(os.getpid()))
 signal.pause()
if mode=="large_event":
 print("x"*(1048576+1));sys.exit(0)
emit("start",package)
for target in selected:
 name=target["name"]
 if mode=="missing" and target==targets[0]:continue
 if mode!="unexecuted":emit("run",package,Test=name)
 if mode=="skip":emit("skip",package,Test=name);continue
 if "-fuzz" in args:
  if mode!="no_phase":
   workers=2 if mode=="parallel" else 1
   emit("output",package,Test=name,Output=f"fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with {workers} workers\\n")
   emit("output",package,Test=name,Output="fuzz: elapsed: 1s, execs: 2 (2/sec), new interesting: 0 (total: 1)\\n")
 else:
  if mode!="no_seeds":
   emit("run",package,Test=name+"/seed#0")
   emit("skip" if mode=="skip_seed" else "pass",package,Test=name+"/seed#0")
 if mode in ("crash","corpus_symlink","oversize_crash","many_crashes","crash_timeout"):
  path=root/package[2:]/"testdata/fuzz"/name/("a"*64);path.parent.mkdir(parents=True,exist_ok=True)
  if mode=="corpus_symlink":path.symlink_to(root/"canary")
  else:path.write_text('go test fuzz v1\\n[]byte("synthetic")\\n')
  if mode=="oversize_crash":path.write_bytes(b'go test fuzz v1\\n'+b'x'*1048576)
  if mode=="many_crashes":
   for n in range(17):(path.parent/f'{n:064x}').write_text('go test fuzz v1\\n[]byte("synthetic'+str(n)+'")\\n')
  if mode=="crash_timeout":signal.pause()
  emit("fail",package,Test=name);emit("fail",package);sys.exit(1)
 emit("pass",package,Test=name)
 if mode=="duplicate":emit("pass",package,Test=name)
emit("pass",package)
if mode=="source_mutation":(root/"canary").write_text("changed synthetic input")
if mode=="malformed":print("not JSON")
sys.exit(7 if mode=="failure" else 0)
''')
        self.fake.chmod(0o755)
        (self.root / "mode").write_text("pass")
        (self.root / "canary").write_text("PRIVATE_INPUT_CANARY")
        for args in (["init", "-q"], ["add", "."], ["-c", "user.name=Fuzz tests", "-c", "user.email=fuzz@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "commit", "-qm", "fixture"]):
            subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def write_registry(self):
        (self.root / "scripts/fuzz-targets.json").write_text(json.dumps(self.registry))

    def run_driver(self, mode="smoke", fake="pass", *extra, timeout=30):
        (self.root / "mode").write_text(fake)
        env = dict(os.environ, EVYDENCE_TEST_DATABASE_URL="PRIVATE_ENV_CANARY", AWS_SECRET_ACCESS_KEY="PRIVATE_ENV_CANARY")
        return subprocess.run([sys.executable, "scripts/fuzz_driver.py", mode, "--go", str(self.fake), "--seconds", "1", "--timeout", "3", "--budget", "20", *extra], cwd=self.root, env=env, capture_output=True, text=True, timeout=timeout)

    def summary(self):
        paths = list((self.root / "tmp/fuzz").glob("*/public/summary.json"))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text())

    def test_smoke_executes_every_registered_target_and_seed(self):
        result = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(len(summary["targets"]), 3)
        self.assertTrue(all(row["status"] == "passed" and row["seeds"] == 1 for row in summary["targets"]))
        args = [json.loads(line) for line in (self.root / "tmp/fake/invocations.jsonl").read_text().splitlines()]
        self.assertEqual(sum("-list" in row for row in args), 1)
        self.assertEqual(sum("-run" in row for row in args), 2)
        keys = json.loads((self.root / "tmp/fake/environment.json").read_text())
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", keys)
        self.assertNotIn("EVYDENCE_TEST_DATABASE_URL", keys)
        self.assertNotIn("PRIVATE_ENV_CANARY", result.stdout + result.stderr + json.dumps(summary))

    def test_campaign_is_serial_one_worker_and_requires_real_phase(self):
        result = self.run_driver("campaign")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["workers"], 1)
        self.assertTrue(all(row["executions"] == 2 for row in summary["targets"]))
        args = [json.loads(line) for line in (self.root / "tmp/fake/invocations.jsonl").read_text().splitlines()]
        campaigns = [row for row in args if "-fuzz" in row]
        self.assertEqual(len(campaigns), 3)
        for row in campaigns:
            for flag in ("-parallel=1", "-p=1", "-count=1", "-fuzztime=1s"):
                self.assertIn(flag, row)

    def test_missing_or_unregistered_discovery_cannot_pass(self):
        for mode in ("missing_discovery", "extra_discovery", "skip_discovery"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as _unused:
                    result = self.run_driver(fake=mode)
                    self.assertNotEqual(result.returncode, 0)
        summaries = list((self.root / "tmp/fuzz").glob("*/public/summary.json"))
        self.assertTrue(all(json.loads(p.read_text())["status"] == "failed" for p in summaries))

    def test_inventory_allows_packages_without_tests_but_runs_every_fuzz_target(self):
        result = self.run_driver(fake="no_test_package")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.summary()["completed_targets"], 3)

    def test_missing_skipped_duplicate_unexecuted_failed_or_malformed_evidence_fails(self):
        for mode in ("missing", "skip", "duplicate", "unexecuted", "failure", "malformed"):
            with self.subTest(mode=mode):
                result = self.run_driver(fake=mode)
                self.assertNotEqual(result.returncode, 0)
        summaries = list((self.root / "tmp/fuzz").glob("*/public/summary.json"))
        self.assertTrue(all(json.loads(p.read_text())["status"] == "failed" for p in summaries))

    def test_campaign_without_phase_or_with_parallel_workers_fails(self):
        for mode in ("no_phase", "parallel"):
            with self.subTest(mode=mode):
                result = self.run_driver("campaign", mode)
                self.assertNotEqual(result.returncode, 0)

    def test_invalid_settings_or_registry_fail_before_go(self):
        for args in (("--seconds", "0"), ("--seconds", "61"), ("--seconds", "1;echo unsafe"), ("--timeout", "0"), ("--timeout", "1201"), ("--budget", "0"), ("--budget", "2701"), ("--workers", "2")):
            with self.subTest(args=args):
                result = self.run_driver("campaign", "pass", *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "tmp/fake/invocations.jsonl").exists())
        self.registry["targets"].append(self.registry["targets"][0])
        self.write_registry()
        self.assertNotEqual(self.run_driver().returncode, 0)
        self.assertFalse((self.root / "tmp/fake/invocations.jsonl").exists())

    def assert_timeout_cleanup(self, fake):
        result = self.run_driver("campaign", fake, "--timeout", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary()["status"], "failed")
        for filename in ("parent.pid", "child.pid"):
            pid = int((self.root / "tmp/fake" / filename).read_text())
            for _ in range(100):
                path = Path(f"/proc/{pid}/stat")
                if not path.exists() or path.read_text().split()[2] == "Z":
                    break
                time.sleep(0.01)
            else:
                self.fail("owned process survived driver timeout")

    def test_timeout_stops_owned_process_tree(self):
        self.assert_timeout_cleanup("block")

    def test_timeout_stops_resistant_grandchild_after_parent_exits(self):
        self.assert_timeout_cleanup("resistant_child")

    def test_missing_or_skipped_seed_evidence_fails(self):
        for fake in ("no_seeds", "skip_seed"):
            with self.subTest(fake=fake):
                self.assertNotEqual(self.run_driver("smoke", fake).returncode, 0)

    def test_non_object_registry_rejected_before_go(self):
        for raw in ('[]', 'null', '42', '"invalid"'):
            with self.subTest(raw=raw):
                (self.root / "scripts/fuzz-targets.json").write_text(raw)
                result = self.run_driver()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse((self.root / "tmp/fake/invocations.jsonl").exists())

    def test_source_changes_and_oversize_events_fail(self):
        for fake in ("source_mutation", "large_event"):
            with self.subTest(fake=fake):
                self.assertNotEqual(self.run_driver(fake=fake).returncode, 0)

    def test_artifact_size_count_and_timeout_accounting(self):
        for fake in ("oversize_crash", "many_crashes", "crash_timeout"):
            with self.subTest(fake=fake):
                result = self.run_driver("campaign", fake, "--timeout", "1")
                self.assertNotEqual(result.returncode, 0)
                summary = sorted((self.root / "tmp/fuzz").glob("*/public/summary.json"), key=lambda p: p.stat().st_mtime_ns)[-1]
                value = json.loads(summary.read_text())
                self.assertEqual(value["status"], "failed")
                self.assertLessEqual(value["crash_count"], 16)
                if fake == "many_crashes":
                    self.assertEqual(value["crash_count"], 16)
                if fake == "crash_timeout":
                    self.assertGreaterEqual(value["crash_count"], 1)
                for path in summary.parent.glob("crashes/**/*"):
                    if path.is_file():
                        self.assertLessEqual(path.stat().st_size, 1048576)
                shutil.rmtree(self.root / "cmd/example/testdata", ignore_errors=True)
                shutil.rmtree(self.root / "internal/a/testdata", ignore_errors=True)

    def test_nonregular_corpus_rejected_without_blocking(self):
        path = self.root / "internal/a/testdata/fuzz/FuzzOne/fifo"
        path.parent.mkdir(parents=True)
        os.mkfifo(path)
        result = self.run_driver(timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "tmp/fake/invocations.jsonl").exists())

    def test_deleted_tracked_file_is_bound_as_dirty_source(self):
        (self.root / "canary").unlink()
        result = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.summary()
        self.assertFalse(summary["source"]["worktree_clean"])
        self.assertEqual(summary["source"], summary["source_after"])

    def test_synthetic_crash_retention_is_bounded_and_source_tied(self):
        result = self.run_driver("campaign", "crash")
        self.assertNotEqual(result.returncode, 0)
        summary = self.summary()
        self.assertEqual(summary["status"], "failed")
        self.assertRegex(summary["source"]["commit"], r"^[0-9a-f]{40}$")
        public = next((self.root / "tmp/fuzz").glob("*/public"))
        crashes = list(public.glob("crashes/**/*"))
        files = [p for p in crashes if p.is_file()]
        self.assertEqual(len(files), 1)
        self.assertIn(b"synthetic", files[0].read_bytes())
        self.assertEqual(summary["crash_count"], 1)

    def test_output_or_corpus_symlinks_cannot_expose_unrelated_files(self):
        output = self.root / "tmp/fuzz"
        output.parent.mkdir(exist_ok=True)
        output.symlink_to(self.root / "elsewhere")
        self.assertNotEqual(self.run_driver().returncode, 0)
        self.assertFalse((self.root / "elsewhere").exists())
        output.unlink()
        result = self.run_driver("campaign", "corpus_symlink")
        self.assertNotEqual(result.returncode, 0)
        for path in (self.root / "tmp/fuzz").glob("*/public/**/*"):
            if path.is_file():
                self.assertNotIn(b"PRIVATE_INPUT_CANARY", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
