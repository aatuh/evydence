#!/usr/bin/env python3
"""Reject drift between declared policy and executable build/CI inputs."""
import copy
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import support_matrix as support
import support_matrix_artifacts as artifacts


ROOT = Path(__file__).resolve().parents[1]


class SupportArtifactTests(unittest.TestCase):
    def setUp(self):
        self.policy = support.load_policy(ROOT)
        self.files = {name: (ROOT / name).read_text() for name in artifacts.ARTIFACTS}

    def check(self, files=None):
        return artifacts.check_artifacts(self.policy, read_text=(self.files if files is None else files).__getitem__)

    def test_repository_build_inputs_match_the_declared_policy(self):
        self.assertEqual(self.check(), [])

    def test_changed_inputs_are_rejected_independently(self):
        self.assertEqual(self.check(), [], "mutation controls require a valid baseline")
        mutations = [
            ("go.mod", "go 1.26.9", "go 1.26.8"),
            ("go.mod", "toolchain go1.27.2", "toolchain go1.27.1"),
            ("Makefile", "GOTOOLCHAIN ?= go1.27.2", "GOTOOLCHAIN ?= go1.26.9"),
            ("Makefile", "GOSEC_VERSION ?= v2.25.0", "GOSEC_VERSION ?= latest"),
            ("Makefile", "export GOTOOLCHAIN\n", "export GOTOOLCHAIN\nGOTOOLCHAIN := go1.26.9\n"),
            ("Dockerfile", "golang:1.27.2-", "golang:1.26.9-"),
            ("Dockerfile", "GOTOOLCHAIN=local", "GOTOOLCHAIN=auto"),
            ("deploy/local-dependencies/Dockerfile", "golang:1.27.2-", "golang:1.26.9-"),
            ("deploy/local-dependencies/Dockerfile", "@sha256:", "@sha256:f"),
            (".github/workflows/ci.yml", "go: ['1.26.9', '1.27.2']", "go: ['1.27.2']"),
            (".github/workflows/ci.yml", "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto"),
            (".github/workflows/ci.yml", "- name: Set up selected Go\n        uses: actions/setup-go@", "- name: Set up selected Go\n        uses: actions/checkout@"),
            (".github/workflows/ci.yml", "- name: Test complete package set with selected compiler\n", "- name: Test complete package set with selected compiler\n        env:\n          GOTOOLCHAIN: auto\n"),
            (".github/workflows/ci.yml", "go: ['1.26.9', '1.27.2']", "go: ['1.26.9', '1.27.2']\n        exclude: [{go: '1.26.9'}]"),
            (".github/workflows/ci.yml", "go test ./... -timeout=30m", "go test ./... -run TestOne -timeout=30m"),
            (".github/workflows/ci.yml", "name: Production Check", "name: Production Check (new)"),
            (".github/workflows/ci.yml", "- name: Set up Go\n", "- name: Set up Go\n        env:\n          GOTOOLCHAIN: local\n"),
            (".github/workflows/ci.yml", "HELM_VERSION: v4.3.0", "HELM_VERSION: latest"),
            (".github/workflows/ci.yml", "OASDIFF_SHA256: 541f", "OASDIFF_SHA256: 541e"),
            (".github/workflows/container-image.yml", "go-version-file: go.mod", "go-version: '1.26.9'"),
            (".github/workflows/container-image.yml", "--platform linux/amd64", "--platform linux/arm64"),
            (".github/workflows/release-artifacts.yml", "go-version-file: go.mod", "go-version: '1.26.9'"),
            ("README.md", "go-1.26.9%20%2F%201.27.2-", "go-1.26.9+-"),
            ("docs/reference/toolchain-platform-support.md", "| Current | `1.27.2` |", "| Current | `1.27.1` |"),
        ]
        for name, before, after in mutations:
            with self.subTest(path=name, before=before):
                files = dict(self.files)
                self.assertIn(before, files[name])
                files[name] = files[name].replace(before, after)
                self.assertTrue(self.check(files), "drift passed silently")

    def test_missing_and_malformed_sources_return_fixed_file_diagnostics(self):
        for name in artifacts.ARTIFACTS:
            with self.subTest(path=name):
                files = dict(self.files)
                del files[name]
                failures = self.check(files)
                self.assertTrue(failures)
                self.assertTrue(all("PRIVATE" not in item for item in failures))
        for raw in ("jobs: [PRIVATE", "jobs: {}\njobs: {PRIVATE: value}", "jobs: PRIVATE"):
            files = dict(self.files)
            files[".github/workflows/ci.yml"] = raw
            self.assertTrue(self.check(files))

    def test_cli_check_uses_the_fixed_checkout_and_fails_on_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in {**self.files, "release/support-matrix.json": (ROOT / "release/support-matrix.json").read_text()}.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
            output, errors = io.StringIO(), io.StringIO()
            self.assertEqual(support.main(["--check"], root=root, stdout=output, stderr=errors), 0)
            self.assertIn("support matrix artifacts are current", output.getvalue())
            (root / "go.mod").write_text("PRIVATE_BROKEN")
            output, errors = io.StringIO(), io.StringIO()
            self.assertEqual(support.main(["--check"], root=root, stdout=output, stderr=errors), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("PRIVATE", errors.getvalue())

    def test_policy_change_cannot_leave_old_artifacts_in_place(self):
        for mutate in (lambda p: p["go"].update(current="1.27.3"),
                       lambda p: p["go"].update(minimum="1.26.10"),
                       lambda p: p["tools"]["gosec"].update(version="v2.26.0")):
            policy = copy.deepcopy(self.policy)
            mutate(policy)
            self.assertTrue(artifacts.check_artifacts(policy, read_text=self.files.__getitem__))

    def test_artifact_reader_rejects_links_special_files_and_oversized_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("PRIVATE_CONTENT")
            path = root / "go.mod"
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                artifacts.read_artifact(root, "go.mod")
            path.unlink()
            path.mkdir()
            with self.assertRaises(ValueError):
                artifacts.read_artifact(root, "go.mod")
            path.rmdir()
            path.write_bytes(b" " * (artifacts.MAX_ARTIFACT_BYTES + 1))
            with self.assertRaises(ValueError):
                artifacts.read_artifact(root, "go.mod")
            path.unlink()
            if hasattr(os, "mkfifo"):
                os.mkfifo(path)
                with self.assertRaises(ValueError):
                    artifacts.read_artifact(root, "go.mod")

    def test_artifact_reader_rechecks_opened_type_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("go 1.26.9\n")
            reader, writer = os.pipe()
            self.addCleanup(os.close, writer)
            with patch.object(artifacts.os, "open", return_value=reader):
                with self.assertRaises(ValueError):
                    artifacts.read_artifact(root, "go.mod")
            with self.assertRaises(OSError):
                os.fstat(reader)


if __name__ == "__main__":
    unittest.main()
