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

    def test_dependency_review_selects_current_before_locking_go(self):
        name = ".github/workflows/dependency-review.yml"
        self.assertIn(name, artifacts.ARTIFACTS, "trusted dependency compiler escaped the build policy")
        workflow = artifacts.yaml.load(self.files[name], Loader=artifacts.UniqueLoader)
        job = workflow["jobs"]["evaluate"]
        self.assertEqual(job["env"]["GOTOOLCHAIN"], "local")
        setup = next(step for step in job["steps"] if step.get("uses") == artifacts.SETUP_GO)
        self.assertNotEqual(setup.get("env", {}).get("GOTOOLCHAIN", job["env"]["GOTOOLCHAIN"]), "local",
                            "setup-go would select the minimum instead of the trusted current compiler")
        for incoming in (None, "local"):
            with self.subTest(incoming=incoming):
                data = copy.deepcopy(workflow)
                step = next(step for step in data["jobs"]["evaluate"]["steps"]
                            if step.get("uses") == artifacts.SETUP_GO)
                if incoming is None:
                    step.pop("env", None)
                else:
                    step["env"] = {"GOTOOLCHAIN": incoming}
                files = dict(self.files)
                files[name] = artifacts.yaml.safe_dump(data, sort_keys=False)
                self.assertIn(name + ": version-file setup can select the minimum compiler", self.check(files))

    def test_supported_compilers_exclude_called_x509_advisory_go_2026_6809(self):
        # https://vuln.go.dev/ID/GO-2026-6809.json affects Certificate.Verify,
        # reached by the Sigstore verifier; both supported lines need the fix.
        for role, value in self.policy['go'].items():
            version = tuple(map(int, value.split('.')))
            with self.subTest(role=role, version=value):
                self.assertTrue((1, 26, 10) <= version < (1, 27, 0) or version >= (1, 27, 3),
                                'declared compiler remains affected by GO-2026-6809')

    def test_gitlab_legacy_builder_cannot_escape_policy_checks(self):
        name = "docs/gitlab/evydence-release-evidence.gitlab-ci.yml"
        files = dict(self.files)
        source = (ROOT / name).read_text()
        files[name] = source.replace("golang:" + self.policy["go"]["current"], "golang:1.25")
        self.assertIn("golang:1.25", files[name])
        self.assertTrue(any(item.startswith(name + ":") and "builder" in item for item in self.check(files)),
                        "GitLab's unsupported compiler escaped the build policy")

    def test_github_examples_cannot_override_the_preferred_compiler(self):
        for name in ("docs/github-actions/release-evidence-workflow.yml",
                     "docs/github-actions/quickstart-release-evidence.yml"):
            with self.subTest(path=name):
                files = dict(self.files)
                source = (ROOT / name).read_text()
                self.assertIn("go-version-file: go.mod", source)
                files[name] = source.replace("go-version-file: go.mod", "go-version: '1.26.10'")
                self.assertTrue(any(item.startswith(name + ":") and "preferred compiler" in item for item in self.check(files)),
                                "CI example silently selected another compiler")

    def test_gitlab_builder_and_environment_drift_are_rejected(self):
        self.assertEqual(self.check(), [], "mutation controls require a valid baseline")
        name = "docs/gitlab/evydence-release-evidence.gitlab-ci.yml"
        template = artifacts.yaml.load(self.files[name], Loader=artifacts.UniqueLoader)
        mutations = [
            lambda data: data["build"].update(image="golang:1.25"),
            lambda data: data["evydence:evidence"].update(image="golang:1.25"),
            lambda data: data["build"].update(image="golang:" + self.policy["go"]["current"]),
            lambda data: data["variables"].update(GOTOOLCHAIN="auto"),
            lambda data: data.pop("variables"),
            lambda data: data["build"].update(variables={"GOTOOLCHAIN": "auto"}),
            lambda data: data["evydence:evidence"].update(variables={"GOTOOLCHAIN": "auto"}),
            lambda data: data["build"].update(inherit={"variables": "false"}),
            lambda data: data["build"].update(script=["export GOTOOLCHAIN=auto", "go build ./cmd/evydence"]),
            lambda data: data.update({"PRIVATE_JOB": {"image": "golang:1.25", "script": ["go build ./..."]}}),
            lambda data: data.update(build="PRIVATE_INVALID"),
            lambda data: data.pop("evydence:evidence"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                data = copy.deepcopy(template)
                mutate(data)
                files = dict(self.files)
                files[name] = artifacts.yaml.safe_dump(data, sort_keys=False)
                failures = self.check(files)
                self.assertTrue(any(item.startswith(name + ":") for item in failures))
                self.assertTrue(all("PRIVATE" not in item for item in failures))
        for raw in ("PRIVATE", "build: {}\nbuild: PRIVATE", "variables: [PRIVATE"):
            files = dict(self.files)
            files[name] = raw
            failures = self.check(files)
            self.assertIn(name + ": invalid template", failures)
            self.assertTrue(all("PRIVATE" not in item for item in failures))

    def test_qa_installation_uses_the_locked_tool_graph(self):
        recipe = self.files["Makefile"].split("\ntools:", 1)[1].split("\nfmt:", 1)[0]
        for package in ("github.com/golangci/golangci-lint/v2/cmd/golangci-lint",
                        "github.com/securego/gosec/v2/cmd/gosec", "golang.org/x/vuln/cmd/govulncheck"):
            self.assertIn("GOWORK=off $(GO) -C tools install -mod=readonly " + package, recipe)
        self.assertNotIn("@$(", recipe, "versioned install must not discard the locked dependency graph")

    def test_changed_inputs_are_rejected_independently(self):
        self.assertEqual(self.check(), [], "mutation controls require a valid baseline")
        mutations = [
            ("go.mod", "go 1.26.10", "go 1.26.8"),
            ("go.mod", "toolchain go1.27.3", "toolchain go1.27.1"),
            ("Makefile", "GOTOOLCHAIN ?= go1.27.3", "GOTOOLCHAIN ?= go1.26.10"),
            ("tools/go.mod", "github.com/securego/gosec/v2 v2.29.0", "github.com/securego/gosec/v2 latest"),
            ("tools/go.mod", "golang.org/x/tools v0.52.0", "golang.org/x/tools v0.49.0"),
            ("tools/go.mod", "toolchain go1.27.3", "toolchain go1.27.1"),
            ("tools/go.mod", "\nrequire (", "\nreplace golang.org/x/tools => ../PRIVATE\nrequire ("),
            ("Makefile", "export GOTOOLCHAIN\n", "export GOTOOLCHAIN\nGOTOOLCHAIN := go1.26.10\n"),
            ("Dockerfile", "golang:1.27.3-", "golang:1.26.10-"),
            ("Dockerfile", "GOTOOLCHAIN=local", "GOTOOLCHAIN=auto"),
            ("deploy/local-dependencies/Dockerfile", "golang:1.27.3-", "golang:1.26.10-"),
            ("deploy/local-dependencies/Dockerfile", "@sha256:", "@sha256:f"),
            (".github/workflows/ci.yml", "go: ['1.26.10', '1.27.3']", "go: ['1.27.3']"),
            (".github/workflows/ci.yml", "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto"),
            (".github/workflows/ci.yml", artifacts.SETUP_GO, "actions/setup-go@v5"),
            (".github/workflows/ci.yml", "- name: Set up selected Go\n        uses: actions/setup-go@", "- name: Set up selected Go\n        uses: actions/checkout@"),
            (".github/workflows/ci.yml", "- name: Test complete package set with selected compiler\n", "- name: Test complete package set with selected compiler\n        env:\n          GOTOOLCHAIN: auto\n"),
            (".github/workflows/ci.yml", "go: ['1.26.10', '1.27.3']", "go: ['1.26.10', '1.27.3']\n        exclude: [{go: '1.26.10'}]"),
            (".github/workflows/ci.yml", "go test ./... -timeout=30m", "go test ./... -run TestOne -timeout=30m"),
            (".github/workflows/ci.yml", "name: Production Check", "name: Production Check (new)"),
            (".github/workflows/ci.yml", "- name: Set up Go\n", "- name: Set up Go\n        env:\n          GOTOOLCHAIN: local\n"),
            (".github/workflows/ci.yml", "HELM_VERSION: v4.3.0", "HELM_VERSION: latest"),
            (".github/workflows/ci.yml", "OASDIFF_SHA256: 541f", "OASDIFF_SHA256: 541e"),
            (".github/workflows/container-image.yml", "go-version-file: go.mod", "go-version: '1.26.10'"),
            (".github/workflows/container-image.yml", "--platform linux/amd64", "--platform linux/arm64"),
            (".github/workflows/release-artifacts.yml", "go-version-file: go.mod", "go-version: '1.26.10'"),
            ("docs/github-actions/release-evidence-workflow.yml", artifacts.SETUP_GO, "actions/setup-go@v5"),
            ("docs/github-actions/release-evidence-workflow.yml", "on:\n", "env:\n  GOTOOLCHAIN: local\non:\n"),
            ("docs/github-actions/quickstart-release-evidence.yml", "      EVYDENCE_API_URL:", "      GOTOOLCHAIN: local\n      EVYDENCE_API_URL:"),
            ("README.md", "go-1.26.10%20%2F%201.27.3-", "go-1.26.10+-"),
            ("docs/reference/toolchain-platform-support.md", "| Current | `1.27.3` |", "| Current | `1.27.1` |"),
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
        def next_patch(value):
            major, minor, patch_number = map(int, value.split('.'))
            return f'{major}.{minor}.{patch_number + 1}'
        for mutate in (lambda p: p["go"].update(current=next_patch(p['go']['current'])),
                       lambda p: p["go"].update(minimum=next_patch(p['go']['minimum'])),
                       lambda p: p["tools"]["gosec"].update(version="v2.26.0"),
                       lambda p: p["tool_build_dependencies"].update({"golang.org/x/tools": "v0.51.0"})):
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
            (root / "go.mod").write_text("go 1.26.10\n")
            reader, writer = os.pipe()
            self.addCleanup(os.close, writer)
            with patch.object(artifacts.os, "open", return_value=reader):
                with self.assertRaises(ValueError):
                    artifacts.read_artifact(root, "go.mod")
            with self.assertRaises(OSError):
                os.fstat(reader)


if __name__ == "__main__":
    unittest.main()
