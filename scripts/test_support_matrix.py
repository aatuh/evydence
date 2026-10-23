#!/usr/bin/env python3
"""Contracts for declared toolchains, tools, and release command ownership."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import support_matrix as support


def policy_fixture():
    return {
        "schema_version": "evydence-support-policy.v1",
        "go": {"minimum": "1.26.9", "current": "1.27.2"},
        "tools": {
            "golangci_lint": {"version": "v2.15.0"},
            "gosec": {"version": "v2.29.0"},
            "govulncheck": {"version": "v1.9.0"},
            "helm": {"version": "v4.3.0", "linux_amd64_sha256": "a" * 64},
            "oasdiff": {"version": "1.29.1", "linux_amd64_sha256": "b" * 64},
        },
        "tool_build_dependencies": {"golang.org/x/tools": "v0.52.0"},
        "release": {
            "cli_targets": ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"],
            "runtime_targets": ["linux/amd64"],
            "server_targets": ["linux/amd64"],
            "server_commands": ["evydence-api", "evydence-worker", "evydence-migrate"],
            "cli_command": "evydence",
        },
        "sdk": {"go": "source-wrapper", "python": "source-wrapper", "typescript": "source-wrapper"},
    }


class SupportPolicyTests(unittest.TestCase):
    def parse(self, data):
        return support.parse_policy(json.dumps(data).encode())

    def test_plan_separates_server_commands_from_cli_build_targets(self):
        policy = self.parse(policy_fixture())
        plan = support.release_plan(policy)
        self.assertEqual([r["target"] for r in plan], policy["release"]["cli_targets"])
        for row in plan:
            expected = ["evydence"]
            if row["target"] == "linux/amd64":
                expected += ["evydence-api", "evydence-worker", "evydence-migrate"]
            self.assertEqual(row["commands"], expected)
            self.assertEqual(row["runtime_target"], row["target"] == "linux/amd64")
        plan[0]["commands"].append("PRIVATE_MUTATION")
        self.assertEqual(policy, policy_fixture(), "query results must not mutate policy")

    def test_unsafe_inconsistent_and_unsupported_declarations_fail_closed(self):
        changes = [
            lambda p: p["go"].update(current="latest"),
            lambda p: p["go"].update(current="1.27.2;PRIVATE_COMMAND"),
            lambda p: p["go"].update(current="1.25.9"),
            lambda p: p["go"].update(minimum=True),
            lambda p: p["go"].update(current="1.27"),
            lambda p: p["go"].update(current="01.27.2"),
            lambda p: p["tools"]["gosec"].update(version="latest"),
            lambda p: p["tools"]["helm"].update(linux_amd64_sha256="PRIVATE_DIGEST"),
            lambda p: p["tools"].pop("govulncheck"),
            lambda p: p["tool_build_dependencies"].update({"golang.org/x/tools": "latest"}),
            lambda p: p["tool_build_dependencies"].update({"PRIVATE_MODULE": "v0.52.0"}),
            lambda p: p["release"]["cli_targets"].append("../../PRIVATE"),
            lambda p: p["release"]["cli_targets"].append("linux/amd64"),
            lambda p: p["release"].update(cli_targets=[]),
            lambda p: p["release"].update(runtime_targets=["windows/amd64"]),
            lambda p: p["release"].update(server_targets=["darwin/arm64"]),
            lambda p: p["release"]["server_commands"].append("PRIVATE_EXECUTABLE"),
            lambda p: p["release"]["server_commands"].append("evydence-api"),
            lambda p: p["release"].update(cli_command="PRIVATE_EXECUTABLE"),
            lambda p: p["sdk"].update(python="published-certified-sdk"),
            lambda p: p.update(PRIVATE_UNKNOWN="PRIVATE_VALUE"),
            lambda p: p["go"].update(PRIVATE_UNKNOWN="PRIVATE_VALUE"),
        ]
        for i, mutate in enumerate(changes):
            with self.subTest(case=i):
                policy = copy.deepcopy(policy_fixture())
                mutate(policy)
                with self.assertRaises(support.PolicyError) as caught:
                    self.parse(policy)
                self.assertNotIn("PRIVATE", str(caught.exception))

    def test_json_is_bounded_strict_and_redacted(self):
        for raw in (b"PRIVATE_BROKEN", b"\xff", b'{} {}', b'{"schema_version":1,"schema_version":2}',
                    b'{"PRIVATE":NaN}', b"[" * 2000 + b"]" * 2000,
                    b" " * (support.MAX_POLICY_BYTES + 1)):
            with self.subTest(size=len(raw)):
                with self.assertRaises(support.PolicyError) as caught:
                    support.parse_policy(raw)
                self.assertNotIn("PRIVATE", str(caught.exception))

    def test_current_and_minimum_are_exact_and_not_silently_promoted(self):
        policy = self.parse(policy_fixture())
        self.assertEqual(support.go_versions(policy), ["1.26.9", "1.27.2"])
        policy["go"]["current"] = "1.26.9"
        self.assertEqual(support.go_versions(policy), ["1.26.9"])

    def test_loader_rejects_special_files_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release").mkdir()
            path = root / "release/support-matrix.json"
            path.mkdir()
            with self.assertRaises(support.PolicyError):
                support.load_policy(root)
            path.rmdir()
            target = root / "PRIVATE.json"
            target.write_text(json.dumps(policy_fixture()))
            path.symlink_to(target)
            with self.assertRaises(support.PolicyError):
                support.load_policy(root)

    def test_loader_bounds_input_and_rechecks_opened_file_type(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release").mkdir()
            path = root / "release/support-matrix.json"
            path.write_bytes(b" " * (support.MAX_POLICY_BYTES + 1))
            with self.assertRaises(support.PolicyError):
                support.load_policy(root)
            path.write_text(json.dumps(policy_fixture()))
            reader, writer = os.pipe()
            self.addCleanup(os.close, writer)
            # Model a regular path replaced by a special file after lstat.
            with patch.object(support.os, "open", return_value=reader):
                with self.assertRaises(support.PolicyError):
                    support.load_policy(root)
            with self.assertRaises(OSError):
                os.fstat(reader)


class SupportPolicyCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "release").mkdir()
        (self.root / "release/support-matrix.json").write_text(json.dumps(policy_fixture()))

    def run_command(self, args):
        output, errors = io.StringIO(), io.StringIO()
        code = support.main(args, root=self.root, stdout=output, stderr=errors)
        return code, output.getvalue(), errors.getvalue()

    def test_queries_return_only_validated_deterministic_data(self):
        for args, expected in ((["--go-minimum"], "1.26.9\n"), (["--go-current"], "1.27.2\n"),
                               (["--tool-version", "gosec"], "v2.29.0\n"),
                               (["--tool-sha256", "helm"], "a" * 64 + "\n"),
                               (["--validate"], "support policy is valid\n")):
            self.assertEqual(self.run_command(args), (0, expected, ""))
        code, data, errors = self.run_command(["--release-plan"])
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(data), support.release_plan(support.parse_policy(json.dumps(policy_fixture()).encode())))
        self.assertEqual(self.run_command(["--go-versions"]), (0, '["1.26.9", "1.27.2"]\n', ""))

    def test_release_queries_preserve_target_order_and_command_ownership(self):
        self.assertEqual(self.run_command(["--release-targets"]),
                         (0, "linux/amd64\nlinux/arm64\ndarwin/amd64\ndarwin/arm64\nwindows/amd64\n", ""))
        for target in policy_fixture()["release"]["cli_targets"]:
            commands = "evydence\n"
            if target == "linux/amd64":
                commands += "evydence-api\nevydence-worker\nevydence-migrate\n"
            self.assertEqual(self.run_command(["--commands", target]), (0, commands, ""))
        policy = policy_fixture()
        policy["release"]["cli_targets"] = ["linux/amd64"]
        (self.root / "release/support-matrix.json").write_text(json.dumps(policy))
        code, output, errors = self.run_command(["--commands", "darwin/arm64"])
        self.assertEqual((code, output), (2, ""))
        self.assertIn("unsupported release target", errors)

    def test_invalid_flags_and_selectors_fail_before_policy_access(self):
        for args in (["--PRIVATE", "PRIVATE_VALUE"], ["--tool-version", "PRIVATE_TOOL"],
                     ["--go-current", "--go-minimum"], ["--tool-sha256", "gosec"],
                     ["--commands", "PRIVATE_TARGET"], ["--commands", "linux/amd64;PRIVATE"],
                     ["--commands", "linux/amd64", "--release-targets"]):
            with self.subTest(args=args), patch.object(support, "load_policy") as load:
                code, output, errors = self.run_command(args)
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertNotIn("PRIVATE", errors)
                load.assert_not_called()

    def test_help_is_independent_of_policy_and_invalid_data_never_leaks(self):
        with patch.object(support, "load_policy") as load:
            code, output, errors = self.run_command(["--help"])
            self.assertEqual((code, errors), (0, ""))
            self.assertIn("--go-current", output)
            load.assert_not_called()
        (self.root / "release/support-matrix.json").write_text("PRIVATE_BROKEN")
        code, output, errors = self.run_command(["--go-current"])
        self.assertEqual((code, output), (1, ""))
        self.assertNotIn("PRIVATE", errors)


if __name__ == "__main__":
    unittest.main()
