import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/local_ci_simulation_check.sh"


class LocalCISimulationTests(unittest.TestCase):
    def run_with_database_stub(self, database_url, create_status=0):
        env = os.environ.copy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "database-calls"
            psql = root / "psql"
            psql.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CI_TEST_DATABASE_CALLS"\n'
                f'exit {create_status}\n'
            )
            psql.chmod(0o700)
            sentinel = root / "go"
            sentinel.write_text("#!/bin/sh\nexit 77\n")
            sentinel.chmod(0o700)
            env.update({
                "PATH": directory + os.pathsep + env["PATH"],
                "EVYDENCE_TEST_DATABASE_URL": database_url,
                "EVYDENCE_LOCAL_CI_SIMULATION_DIR": str(root / "work"),
                "EVYDENCE_LOCAL_CI_KEEP_ARTIFACTS": "0",
                "CI_TEST_DATABASE_CALLS": str(calls),
            })
            result = subprocess.run(
                ["sh", str(SCRIPT)], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=10,
            )
            statements = calls.read_text() if calls.exists() else ""
        return result, statements

    def test_failed_schema_creation_never_drops_unowned_schema(self):
        result, statements = self.run_with_database_stub(
            "postgres://operator@example.test/test", create_status=1,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not create an isolated PostgreSQL schema", result.stderr)
        self.assertEqual(statements.count("CREATE SCHEMA"), 1)
        self.assertNotIn("DROP SCHEMA", statements)

    def test_invalid_database_uri_has_no_database_effects_or_secret_echo(self):
        result, statements = self.run_with_database_stub(
            "https://operator:private-password@example.test/test",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("a PostgreSQL URI is required", result.stderr)
        self.assertNotIn("private-password", result.stderr)
        self.assertEqual(statements, "")

    def test_startup_options_cannot_override_schema_isolation(self):
        result, statements = self.run_with_database_stub(
            "postgres://operator@example.test/test?options=-csearch_path%3Dpublic",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("URI startup options are not supported", result.stderr)
        self.assertEqual(statements, "")

    def test_requires_database_before_opening_resources(self):
        env = os.environ.copy()
        env.pop("EVYDENCE_TEST_DATABASE_URL", None)
        # A retired script must fail before its first build. The sentinel
        # avoids spawning a real compiler if that early guard regresses.
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "go"
            sentinel.write_text("#!/bin/sh\nexit 77\n")
            sentinel.chmod(0o700)
            env["PATH"] = directory + os.pathsep + env["PATH"]
            result = subprocess.run(
                ["sh", str(SCRIPT)], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("EVYDENCE_TEST_DATABASE_URL is required", result.stderr)
        self.assertNotIn("API process exited", result.stderr)

    def test_uses_native_profile_and_owned_schema_cleanup(self):
        source = SCRIPT.read_text()
        self.assertNotIn("EVYDENCE_RUNTIME_PROFILE=local_memory", source)
        self.assertIn("EVYDENCE_RUNTIME_PROFILE=postgres", source)
        self.assertIn('EVYDENCE_DATABASE_URL="$database_url"', source)
        self.assertIn('query["search_path"] = schema', source)
        self.assertIn('CREATE SCHEMA $schema', source)
        self.assertIn('DROP SCHEMA $schema CASCADE', source)
        self.assertIn('if [ "$schema_created" = "1" ]', source)

    def test_runs_worker_and_waits_for_payload_finalization(self):
        source = SCRIPT.read_text()
        self.assertIn('go build -o "$workdir/evydence-worker"', source)
        self.assertIn('worker_pid="$!"', source)
        self.assertIn('wait_for_worker', source)
        self.assertIn('FROM $schema.object_payloads WHERE status', source)
        self.assertIn("FROM $schema.outbox_jobs WHERE status <> 'succeeded'", source)


if __name__ == "__main__":
    unittest.main()
