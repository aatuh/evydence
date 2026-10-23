#!/usr/bin/env python3
"""Regression tests for release-truth changelog validation."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml


SCRIPT = Path(__file__).with_name("check_release_truth.py")
SPEC = importlib.util.spec_from_file_location("check_release_truth", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load release-truth checker")
RELEASE_TRUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_TRUTH)


class ReleaseTruthTests(unittest.TestCase):
    def test_full_truth_gate_accepts_no_default_withdrawal_but_rejects_old_commands(self):
        original_root = RELEASE_TRUTH.ROOT
        metadata = json.loads((original_root / 'release/current.json').read_text())
        tag = metadata['current_public_release']['tag']
        policy = json.loads((original_root / 'release/lifecycle-policy.json').read_text())
        policy['withdrawals'] = [{
            'tag': tag, 'source_commit': metadata['current_public_release']['source_commit'],
            'recorded_at': '2000-01-01T00:00:00Z', 'reason': 'Synthetic test withdrawal only.',
            'notice_url': 'https://github.com/aatuh/evydence/releases/tag/' + tag,
            'replacement_tag': None,
        }]
        warning = f'No default install is available. `{tag}` is WITHDRAWN.\n'
        documents = {}
        for path in RELEASE_TRUTH.INSTALL_GUIDES:
            original = (original_root / path).read_text()
            kept = [line for line in original.splitlines()
                    if not any(marker in line for marker in ['TAG=' + tag, 'dist/' + tag,
                                                             'gh release download ' + tag])]
            documents[path] = warning + '\n'.join(kept)
        def read(path):
            return documents[path] if path in documents else (original_root / path).read_text()
        def git(*args):
            return subprocess.run(['git', *args], cwd=original_root, capture_output=True, text=True)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'release').mkdir()
            metadata_path = root / 'release/current.json'
            metadata_path.write_text(json.dumps(metadata))
            (root / 'release/lifecycle-policy.json').write_text(json.dumps(policy))
            with mock.patch.object(RELEASE_TRUTH, 'ROOT', root), \
                 mock.patch.object(RELEASE_TRUTH, 'METADATA_PATH', metadata_path), \
                 mock.patch.object(RELEASE_TRUTH, 'read', side_effect=read), \
                 mock.patch.object(RELEASE_TRUTH, 'run_git', side_effect=git), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(RELEASE_TRUTH.main(), 0)
                documents['README.md'] += '\ngh release download ' + tag
                self.assertEqual(RELEASE_TRUTH.main(), 1)

    def test_withdrawn_install_docs_warn_without_recommending_the_old_install(self):
        tag = 'v1.2.3-rc.1'
        warning = f'No default install is available. `{tag}` is WITHDRAWN. Historical evidence remains.'
        self.assertTrue(RELEASE_TRUTH.withdrawn_install_document_valid(warning, tag))
        self.assertTrue(RELEASE_TRUTH.withdrawn_install_document_valid(
            warning + '\nA different version: gh release download ' + tag + '0', tag))
        for unsafe in ['', 'WITHDRAWN ' + tag,
                       warning + '\ngh release download ' + tag,
                       warning + '\nmake public-release-verify TAG=' + tag,
                       warning + '\nmkdir -p dist/' + tag]:
            with self.subTest(unsafe=unsafe):
                self.assertFalse(RELEASE_TRUTH.withdrawn_install_document_valid(unsafe, tag))

    def test_public_default_is_policy_selected_and_guarded_before_download(self):
        source = (SCRIPT.parent / 'public_release_verify.sh').read_text()
        self.assertTrue(RELEASE_TRUTH.public_release_selection_valid(source))
        selection = 'tag="$(env -i PATH="$PATH" python3 scripts/release_lifecycle.py default-tag)"'
        guard = 'env -i PATH="$PATH" python3 scripts/release_lifecycle.py check-tag "$tag"'
        for marker in [selection, guard]:
            self.assertFalse(RELEASE_TRUTH.public_release_selection_valid(source.replace(marker, '')))
        late_guard = source.replace(guard, '') + '\n' + guard + '\n'
        self.assertFalse(RELEASE_TRUTH.public_release_selection_valid(late_guard))

    def test_container_dispatch_requires_explicit_ref_and_tag(self) -> None:
        path = SCRIPT.parent.parent / '.github/workflows/container-image.yml'
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        self.assertTrue(RELEASE_TRUTH.container_dispatch_valid(workflow))
        inputs = workflow['on']['workflow_dispatch']['inputs']
        for name in ['ref', 'image_tag']:
            with self.subTest(name=name, mutation='default'):
                inputs[name]['default'] = 'v0.1.0-rc.7'
                self.assertFalse(RELEASE_TRUTH.container_dispatch_valid(workflow))
                del inputs[name]['default']
            with self.subTest(name=name, mutation='optional'):
                inputs[name]['required'] = 'false'
                self.assertFalse(RELEASE_TRUTH.container_dispatch_valid(workflow))
                inputs[name]['required'] = 'true'
        self.assertFalse(RELEASE_TRUTH.container_dispatch_valid({}))

    def test_no_unreleased_changes_is_not_an_entry(self) -> None:
        changelog = "# Changelog\n\n## Unreleased\n\n- No unreleased changes.\n\n## v0.1.0-rc.7 - 2026-06-01\n"

        self.assertFalse(RELEASE_TRUTH.unreleased_section_has_entries(changelog))

    def test_unreleased_change_is_an_entry(self) -> None:
        changelog = "# Changelog\n\n## Unreleased\n\n### Added\n\n- Customer package proof summary.\n\n## v0.1.0-rc.7 - 2026-06-01\n"

        self.assertTrue(RELEASE_TRUTH.unreleased_section_has_entries(changelog))

    def test_user_visible_commit_detection_ignores_only_maintenance_types(self) -> None:
        subjects = ["test: add smoke test", "ci: tighten workflow", "feat: add evidence export"]

        self.assertTrue(RELEASE_TRUTH.has_user_visible_commit(subjects))
        self.assertFalse(RELEASE_TRUTH.has_user_visible_commit(["test: add smoke test", "chore: refresh fixture"]))


if __name__ == "__main__":
    unittest.main()
