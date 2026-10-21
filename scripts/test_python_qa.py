#!/usr/bin/env python3
"""Python QA pinning, installation boundaries and SDK import regressions."""
import importlib.metadata
from pathlib import Path
import tempfile
import unittest

import yaml
import python_qa

ROOT = Path(__file__).resolve().parents[1]
HASH = 'a' * 64


class RequirementsTests(unittest.TestCase):
    def test_exact_pin_and_multiple_artifact_hashes_are_retained(self):
        raw = ('# source reference\nPyYAML==6.0.3 \\\n  --hash=sha256:' + HASH + ' \\\n  --hash=sha256:' + 'b' * 64 + '\n').encode()
        version, hashes = python_qa.parse_requirements(raw)
        self.assertEqual(version, '6.0.3')
        self.assertEqual(hashes, [HASH, 'b' * 64])

    def test_unpinned_unhashed_extra_options_packages_and_malformed_hashes_fail(self):
        for raw in [b'', b'PyYAML>=6.0.3', b'PyYAML==6.0.3',
                    b'--index-url https://SECRET_CANARY', b'\xff', b' ' * 32769,
                    ('PyYAML==6.0.3 --hash=sha256:' + HASH + ' --no-deps').encode(),
                    ('PyYAML==6.0.3 --hash=sha256:' + HASH + '\nrequests==1.0').encode(),
                    b'PyYAML==6.0.3 --hash=sha256:bad',
                    ('PyYAML==6.0.3 --hash=sha256:' + HASH + ' --hash=sha256:' + HASH).encode()]:
            with self.subTest(length=len(raw)), self.assertRaises(python_qa.PythonQAError) as failure:
                python_qa.parse_requirements(raw)
            self.assertNotIn('SECRET_CANARY', str(failure.exception))

    def test_installed_version_and_transitive_requirements_cannot_drift_silently(self):
        class Distribution:
            version = '6.0.3'
            requires = None
        distribution = Distribution()
        python_qa.check_distribution(distribution, '6.0.3')
        for version, requirements in [('6.0.2', None), ('6.0.3', ['other>=1']), ('6.0.3', 'invalid')]:
            distribution.version, distribution.requires = version, requirements
            with self.subTest(version=version), self.assertRaises(python_qa.PythonQAError):
                python_qa.check_distribution(distribution, '6.0.3')

    def test_python_sdk_static_imports_stay_standard_library_or_local(self):
        python_qa.check_sdk(ROOT)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); sdk = root / 'sdk/python'; sdk.mkdir(parents=True)
            (sdk / 'client.py').write_text('import urllib.request\nfrom local import Thing\n')
            (sdk / 'local.py').write_text('class Thing: pass\n')
            python_qa.check_sdk(root)
            (sdk / 'client.py').write_text('import requests\n')
            with self.assertRaises(python_qa.PythonQAError):
                python_qa.check_sdk(root)
            (sdk / 'client.py').write_text('from ..outside import Thing\n')
            with self.assertRaises(python_qa.PythonQAError):
                python_qa.check_sdk(root)

    def test_repository_pin_and_installed_distribution_agree(self):
        version, hashes = python_qa.parse_requirements((ROOT / 'tools/requirements-qa.txt').read_bytes())
        self.assertTrue(hashes)
        python_qa.check_distribution(importlib.metadata.distribution('PyYAML'), version)


class WorkflowTests(unittest.TestCase):
    def test_qa_and_packaging_install_hashed_wheels_in_isolated_venvs(self):
        for name, job in [('ci.yml', 'production-check'), ('release-artifacts.yml', 'package')]:
            with self.subTest(workflow=name):
                workflow = yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)
                steps = workflow['jobs'][job]['steps']
                installs = [step for step in steps if 'requirements-qa.txt' in step.get('run', '')]
                self.assertEqual(len(installs), 1)
                run = installs[0]['run']
                self.assertIn('python3 -m venv ', run)
                self.assertIn('--isolated', run)
                self.assertIn('--require-hashes', run)
                self.assertIn('--only-binary=:all:', run)
                self.assertIn('GITHUB_PATH', run)
                self.assertIn('python3-venv', run)
                for forbidden in ['--system-site-packages', '--no-deps', '--trusted-host', 'sudo pip', 'curl ', 'python3-yaml']:
                    self.assertNotIn(forbidden, run)
                all_commands = '\n'.join(step.get('run', '') for step in steps)
                self.assertNotIn('python3-yaml', all_commands)
                installation = steps.index(installs[0])
                gates = [index for index, step in enumerate(steps)
                         if 'make production-check' in step.get('run', '')
                         or 'scripts/release_candidate_package.sh' in step.get('run', '')]
                self.assertTrue(gates)
                self.assertTrue(all(installation < index for index in gates))


if __name__ == '__main__':
    unittest.main()
