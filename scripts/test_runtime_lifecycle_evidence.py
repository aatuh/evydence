#!/usr/bin/env python3
"""Negative contracts for required release-binary shutdown evidence."""
import json
from pathlib import Path
import tempfile
import unittest

import runtime_lifecycle_evidence as evidence


class RuntimeLifecycleEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.records = {}
        for name in evidence.CASES:
            forced = name.endswith("Forced")
            record = {"schema_version": "evydence-lifecycle-case.v1.0.0", "case": name,
                      "status": "passed", "forced": forced, "database_lock_barrier": True,
                      "initial_exit_code": 1 if forced else 0}
            if "API" in name:
                record.update(process="api", restart_exit_code=0, projects=1, project_audit_entries=1,
                              completed_idempotency_records=1, post_stop_projects=0 if forced else 1,
                              writer_exclusion_during_work=True)
            else:
                record.update(process="worker", attempts=2 if forced else 1, success_outcomes=1,
                              failure_outcomes=0, finalized_payloads=1, restart_exit_code=0 if forced else None, payload_digest="sha256:" + "a" * 64)
            self.records[name] = record
        self.write()

    def write(self, actions=None):
        actions = actions or {name: "pass" for name in evidence.CASES}
        events = [{"Action": action, "Package": evidence.PACKAGE, "Test": name}
                  for name, action in actions.items()]
        events.append({"Action": "pass", "Package": evidence.PACKAGE})
        (self.root / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
        for name, receipt in self.records.items():
            directory = self.root / name
            directory.mkdir(exist_ok=True)
            (directory / "receipt.json").write_text(json.dumps(receipt))

    def test_all_four_process_results_and_durable_receipts_are_required(self):
        result = evidence.verify(self.root, 0)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(len(result["cases"]), 4)

    def test_missing_skipped_failed_and_duplicate_go_passes_cannot_pass(self):
        for action in ("skip", "fail", "missing", "duplicate"):
            with self.subTest(action=action):
                actions = {name: "pass" for name in evidence.CASES}
                name = evidence.CASES[0]
                if action == "missing":
                    del actions[name]
                else:
                    actions[name] = action if action != "duplicate" else "pass"
                self.write(actions)
                if action == "duplicate":
                    with (self.root / "events.jsonl").open("a") as output:
                        output.write(json.dumps({"Action": "pass", "Package": evidence.PACKAGE, "Test": name}) + "\n")
                self.assertEqual(evidence.verify(self.root, 0)["status"], "failed")

    def test_go_failure_or_malformed_events_cannot_pass(self):
        self.assertEqual(evidence.verify(self.root, 2)["status"], "failed")
        with (self.root / "events.jsonl").open("a") as output:
            output.write("raw-private-canary\n")
        result = evidence.verify(self.root, 0)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("raw-private-canary", json.dumps(result))

    def test_false_completion_or_missing_receipt_cannot_pass(self):
        name = "TestReleaseBinaryWorkerForced"
        self.records[name]["success_outcomes"] = 2
        self.write()
        self.assertEqual(evidence.verify(self.root, 0)["status"], "failed")
        self.records[name]["success_outcomes"] = 1
        self.write()
        (self.root / name / "receipt.json").unlink()
        self.assertEqual(evidence.verify(self.root, 0)["status"], "failed")

    def test_structurally_invalid_event_cannot_pass(self):
        with (self.root / "events.jsonl").open("a") as output:
            output.write(json.dumps({"Package": evidence.PACKAGE}) + "\n")
        self.assertEqual(evidence.verify(self.root, 0)["status"], "failed")

    def test_receipt_symlink_is_rejected_without_reading_target(self):
        name = evidence.CASES[0]
        receipt = self.root / name / "receipt.json"
        receipt.unlink()
        target = self.root / "private-target"
        target.write_text("private-canary")
        receipt.symlink_to(target)
        result = evidence.verify(self.root, 0)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("private-canary", json.dumps(result))
        self.assertEqual(target.read_text(), "private-canary")


if __name__ == "__main__":
    unittest.main()
