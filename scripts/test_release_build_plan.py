#!/usr/bin/env python3
"""Exercise the real packaging entry point without builds or signing material."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import support_matrix as support


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release_candidate_package.sh"


class ReleaseBuildPlanTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.marker = self.root / "unexpected-command"
        self.environment = dict(os.environ)
        self.environment.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                                EVYDENCE_TEST_DATABASE_URL="",
                                EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64="",
                                RELEASE_SIGNING_PRIVATE_KEY_B64="")
        for name in ("git", "go", "make", "tar", "zip", "sha256sum"):
            self.stub(name, '#!/bin/sh\nprintf unexpected > "$PLAN_TEST_MARKER"\nexit 91\n')
        self.environment["PLAN_TEST_MARKER"] = str(self.marker)

    def stub(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o700)

    def run_plan(self, *args):
        return subprocess.run(["bash", str(SCRIPT), *args], cwd=self.root,
                              env=self.environment, capture_output=True, text=True, timeout=10)

    def test_plan_is_read_only_and_matches_the_actual_policy(self):
        result = self.run_plan("--plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), support.release_plan(support.load_policy(ROOT)))
        self.assertEqual(result.stderr, "")
        self.assertFalse(self.marker.exists(), "plan must not use Git, Go, Make or signing material")

    def test_unknown_extra_plan_arguments_fail_before_external_commands(self):
        result = self.run_plan("--plan", "PRIVATE_ARGUMENT")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("PRIVATE", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_unsafe_tags_fail_before_external_commands(self):
        for tag in ("../PRIVATE", "/PRIVATE", "v0.0.0-rc.1;PRIVATE", "v0.0.0-rc.$(PRIVATE)", "v0.0.0-rc.1\nPRIVATE"):
            with self.subTest(tag=tag):
                result = self.run_plan(tag)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("PRIVATE", result.stderr)
                self.assertFalse(self.marker.exists())

    def prepare_clean_checkout(self, version):
        self.stub("git", '''#!/bin/sh
case "$*" in
  "rev-parse -q --verify refs/tags/"*) exit 1 ;;
  *) exit 0 ;;
esac
''')
        self.stub("go", '#!/bin/sh\n[ "$*" = "env GOVERSION" ] || exit 92\nprintf "%s\\n" "'+version+'"\n')

    def test_wrong_compiler_is_rejected_before_dependency_or_signing_work(self):
        self.prepare_clean_checkout("go1.26.9")
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires the declared current Go compiler", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_current_compiler_still_requires_live_dependency_configuration(self):
        self.prepare_clean_checkout("go"+support.load_policy(ROOT)["go"]["current"])
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 2)
        self.assertIn("EVYDENCE_TEST_DATABASE_URL is required", result.stderr)
        self.assertFalse(self.marker.exists())

    def isolate_runtime_path(self):
        for name in ("bash", "dirname", "python3"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, name)
            (self.bin / name).symlink_to(executable)
        self.environment["PATH"] = str(self.bin)

    def test_missing_archive_tool_stops_before_validation_or_artifact_writes(self):
        self.isolate_runtime_path()
        for missing in ("zip", "tar", "sha256sum"):
            with self.subTest(missing=missing):
                self.prepare_gate_result("unchanged")
                self.marker.unlink(missing_ok=True)
                gate_state = Path(self.environment["PLAN_TEST_STATE"])
                gate_state.unlink(missing_ok=True)
                for name in ("tar", "zip", "sha256sum"):
                    self.stub(name, '#!/bin/sh\nprintf unexpected > "$PLAN_TEST_MARKER"\nexit 91\n')
                (self.bin / missing).unlink()
                result = self.run_plan("v0.0.0-rc.1401")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("requires archive tool: " + missing, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse(gate_state.exists(), "missing tools must stop before the production gate")
                self.assertFalse(self.marker.exists(), "missing tools must stop before artifact writes")

    def test_plan_does_not_require_archive_tools(self):
        self.isolate_runtime_path()
        for name in ("tar", "zip", "sha256sum"):
            (self.bin / name).unlink()
        result = self.run_plan("--plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), support.release_plan(support.load_policy(ROOT)))
        self.assertEqual(result.stderr, "")
        self.assertFalse(self.marker.exists())

    def prepare_gate_result(self, mode):
        self.prepare_clean_checkout("go"+support.load_policy(ROOT)["go"]["current"])
        self.environment.update(PLAN_TEST_MODE=mode, PLAN_TEST_STATE=str(self.root / "gate-finished"),
                                EVYDENCE_TEST_DATABASE_URL="unused-test-fixture",
                                EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64=base64.b64encode(bytes(64)).decode())
        self.stub("git", '''#!/bin/sh
case "$*" in
  "rev-parse -q --verify refs/tags/"*) exit 1 ;;
  "rev-parse --verify HEAD")
    if [ -f "$PLAN_TEST_STATE" ] && [ "$PLAN_TEST_MODE" = head ]; then
      printf '%s\\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    else
      printf '%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    fi ;;
  "status --porcelain --untracked-files=all")
    if [ -f "$PLAN_TEST_STATE" ] && [ "$PLAN_TEST_MODE" = git-error ]; then
      exit 93
    fi
    if [ -f "$PLAN_TEST_STATE" ] && [ "$PLAN_TEST_MODE" = dirty ]; then
      printf '%s\\n' ' M source.go'
    fi ;;
  *) exit 0 ;;
esac
''')
        self.stub("make", '''#!/bin/sh
case "$*" in
  production-check) printf finished > "$PLAN_TEST_STATE" ;;
  "--silent --no-print-directory reproducible-build-check TAG=v0.0.0-rc.1401") exit 0 ;;
  *) exit 92 ;;
esac
''')
        # Any attempt to replace artifacts is intercepted, including when the
        # real script has no post-gate source guard. This fixture never builds,
        # signs, connects to a database or removes repository files.
        self.stub("rm", '#!/bin/sh\nprintf forbidden > "$PLAN_TEST_MARKER"\nexit 91\n')

    def test_release_only_options_are_consumed_before_child_commands(self):
        for alias in ("canonical", "legacy"):
            with self.subTest(alias=alias):
                self.prepare_gate_result("unchanged")
                self.marker.unlink(missing_ok=True)
                if alias == "canonical":
                    git = self.bin / "git"
                    git.write_text(git.read_text().replace('refs/tags/"*) exit 1', 'refs/tags/"*) exit 0', 1))
                self.environment.update(EVYDENCE_RELEASE_ALLOW_EXISTING_TAG="1",
                                        RELEASE_SIGNING_PRIVATE_KEY_B64="PRIVATE_INVALID")
                if alias == "legacy":
                    self.environment["RELEASE_SIGNING_PRIVATE_KEY_B64"] = self.environment["EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64"]
                    self.environment["EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64"] = ""
                guard = ('#!/bin/sh\n'
                         'if [ "${EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64+x}'
                         '${RELEASE_SIGNING_PRIVATE_KEY_B64+x}'
                         '${EVYDENCE_RELEASE_ALLOW_EXISTING_TAG+x}'
                         '${signing_key_b64+x}${release_allow_existing_tag+x}" ]; then exit 89; fi\n')
                # All native preflight and validation children must be clear,
                # including empty exports and inherited internal variable names.
                self.environment.update(signing_key_b64="PRIVATE_INHERITED",
                                        release_allow_existing_tag="PRIVATE_INHERITED")
                for name in ("git", "go", "make"):
                    path = self.bin / name
                    path.write_text(path.read_text().replace("#!/bin/sh\n", guard, 1))
                result = self.run_plan("v0.0.0-rc.1401")
                self.assertEqual(result.returncode, 91, result.stderr)
                self.assertEqual(self.marker.read_text(), "forbidden")
                self.assertNotIn("PRIVATE", result.stdout + result.stderr)
                key = base64.b64encode(bytes(64)).decode()
                self.assertNotIn(key, result.stdout + result.stderr)

    def test_dirty_source_after_validation_stops_before_artifact_changes(self):
        self.prepare_gate_result("dirty")
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("source changed during validation", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_changed_commit_after_validation_stops_before_artifact_changes(self):
        self.prepare_gate_result("head")
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("source changed during validation", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_unchanged_source_reaches_the_intercepted_artifact_phase(self):
        self.prepare_gate_result("unchanged")
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 91, result.stderr)
        self.assertEqual(self.marker.read_text(), "forbidden")

    def test_failed_reproducibility_gate_stops_before_artifact_replacement_or_signing(self):
        self.prepare_gate_result("unchanged")
        self.stub("make", '''#!/bin/sh
case "$*" in
  production-check) printf finished > "$PLAN_TEST_STATE" ;;
  "--silent --no-print-directory reproducible-build-check TAG=v0.0.0-rc.1401") exit 94 ;;
  *) exit 92 ;;
esac
''')
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 94, result.stderr)
        self.assertFalse(self.marker.exists(), "failed comparison must preserve artifacts and stop signing")

    def test_git_failure_after_validation_stops_before_artifact_changes(self):
        self.prepare_gate_result("git-error")
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 93, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_git_status_failure_prevents_validation_work(self):
        self.stub("git", '''#!/bin/sh
case "$*" in
  "status --porcelain --untracked-files=all") exit 94 ;;
  *) exit 0 ;;
esac
''')
        result = self.run_plan("v0.0.0-rc.1401")
        self.assertEqual(result.returncode, 94, result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
