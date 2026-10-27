#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import paired_backup_manifest as paired


class PairedBackupManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "database.dump"
        self.database.write_bytes(b"postgres-backup-v1")
        self.objects = self.root / "objects"
        (self.objects / "tenants/ten_1/payloads").mkdir(parents=True)
        (self.objects / "tenants/ten_1/payloads/a").write_bytes(b"payload")
        (self.objects / "tenants/ten_1/payloads/a.json").write_text('{"digest":"sha256:test"}\n', encoding="utf-8")
        self.migrations = self.root / "migrations"
        self.migrations.mkdir()
        (self.migrations / "20260101000000_init.up.sql").write_text("CREATE TABLE example(id text);\n", encoding="utf-8")
        (self.migrations / "20260101000000_init.down.sql").write_text("DROP TABLE example;\n", encoding="utf-8")
        self.commit = "a" * 40
        self.checkpoint_id = "backup_tenant_001"
        self.state_hash = "sha256:" + "b" * 64

    def manifest(self) -> dict:
        return paired.build_manifest(
            self.database,
            self.objects,
            self.migrations,
            self.commit,
            self.checkpoint_id,
            self.state_hash,
        )

    def test_manifest_is_deterministic_and_contains_only_backup_identity(self) -> None:
        first = self.manifest()
        second = self.manifest()
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], paired.SCHEMA_VERSION)
        self.assertEqual(first["release_commit"], self.commit)
        self.assertEqual(first["consistency_checkpoint"]["id"], self.checkpoint_id)
        self.assertEqual(first["consistency_checkpoint"]["state_hash"], self.state_hash)
        encoded = json.dumps(first)
        self.assertNotIn("postgres-backup-v1", encoded)
        self.assertNotIn("payload\"", encoded)
        self.assertTrue(first["generation_id"].startswith("sha256:"))
        self.assertEqual(paired.verify_manifest(first, self.database, self.objects, self.migrations, self.commit), [])

    def test_non_object_manifest_is_rejected_before_file_access(self) -> None:
        for value in (None, [], "synthetic", 0, True):
            with self.subTest(value=value), mock.patch.object(
                paired, "file_identity", side_effect=AssertionError("invalid manifest reached backup files")
            ):
                with self.assertRaisesRegex(ValueError, "invalid paired backup manifest"):
                    paired.verify_manifest(value, self.database, self.objects, self.migrations, self.commit)

    def test_malformed_manifest_cli_returns_controlled_error(self) -> None:
        path = self.root / 'manifest.json'
        args = SimpleNamespace(command='verify', manifest=path, database_dump=self.database,
                               objects_dir=self.objects, migrations_dir=self.migrations,
                               release_commit=self.commit)
        for raw in ('[]', 'null', '[' * 1100 + ']' * 1100):
            with self.subTest(length=len(raw)):
                path.write_text(raw)
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(paired, 'arguments', return_value=args), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                        mock.patch.object(paired, 'file_identity', side_effect=AssertionError('invalid input reached backup files')):
                    self.assertEqual(paired.main(), 2)
                self.assertIn('paired backup preflight error:', stderr.getvalue())
                self.assertNotIn('Traceback', stdout.getvalue() + stderr.getvalue())

    def test_manifest_parser_recursion_error_returns_controlled_error(self) -> None:
        path = self.root / 'manifest.json'
        path.write_text('{}')
        args = SimpleNamespace(command='verify', manifest=path, database_dump=self.database,
                               objects_dir=self.objects, migrations_dir=self.migrations,
                               release_commit=self.commit)
        stderr = io.StringIO()
        with mock.patch.object(paired, 'arguments', return_value=args), \
                mock.patch.object(paired.json, 'loads', side_effect=RecursionError('synthetic JSON nesting limit')), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(paired.main(), 2)
        self.assertIn('paired backup preflight error:', stderr.getvalue())

    def test_database_newer_than_object_generation_fails_preflight(self) -> None:
        manifest = self.manifest()
        self.database.write_bytes(b"postgres-backup-v2-after-checkpoint")
        failures = paired.verify_manifest(manifest, self.database, self.objects, self.migrations, self.commit)
        self.assertIn("database backup does not match paired generation", failures)
        self.assertNotIn("object backup does not match paired generation", failures)

    def test_objects_newer_than_database_generation_fails_preflight(self) -> None:
        manifest = self.manifest()
        (self.objects / "tenants/ten_1/payloads/b").write_bytes(b"newer-object")
        failures = paired.verify_manifest(manifest, self.database, self.objects, self.migrations, self.commit)
        self.assertIn("object backup does not match paired generation", failures)
        self.assertNotIn("database backup does not match paired generation", failures)

    def test_schema_and_release_mismatch_fail_preflight(self) -> None:
        manifest = self.manifest()
        (self.migrations / "20260102000000_next.up.sql").write_text("ALTER TABLE example ADD COLUMN value text;\n", encoding="utf-8")
        failures = paired.verify_manifest(manifest, self.database, self.objects, self.migrations, "c" * 40)
        self.assertIn("migration/schema identity does not match paired generation", failures)
        self.assertIn("release commit does not match paired generation", failures)

    def test_object_inventory_rejects_symlink(self) -> None:
        target = self.root / "outside"
        target.write_bytes(b"outside")
        link = self.objects / "tenants/ten_1/payloads/link"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "contains symlink"):
            paired.object_inventory(self.objects)

    def test_generation_id_tampering_fails(self) -> None:
        manifest = self.manifest()
        manifest["generation_id"] = "sha256:" + "0" * 64
        failures = paired.verify_manifest(manifest, self.database, self.objects, self.migrations, self.commit)
        self.assertIn("paired backup manifest generation id is invalid", failures)

    def test_invalid_checkpoint_rejected(self) -> None:
        with self.assertRaises(ValueError):
            paired.build_manifest(self.database, self.objects, self.migrations, self.commit, "bad\ncheckpoint", self.state_hash)
        with self.assertRaises(ValueError):
            paired.build_manifest(self.database, self.objects, self.migrations, self.commit, self.checkpoint_id, "sha256:ABC")


if __name__ == "__main__":
    unittest.main()
