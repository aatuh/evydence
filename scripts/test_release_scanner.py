#!/usr/bin/env python3
"""Exercise scanner environment and bounded process output with tiny subprocesses."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_scanner


class ScannerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.program = self.root / 'scanner'

    def program_text(self, body):
        self.program.write_text('#!/usr/bin/python3\n' + body)
        self.program.chmod(0o700)

    def test_children_receive_no_ambient_credentials_flags_or_configuration(self):
        parent = {'PATH': '/PRIVATE_CANARY/bin', 'HOME': '/PRIVATE_CANARY/home',
                  'GITHUB_TOKEN': 'SECRET_CANARY', 'DATABASE_URL': 'SECRET_CANARY',
                  'SYFT_REGISTRY_AUTH_PASSWORD': 'SECRET_CANARY', 'GOFLAGS': 'SECRET_CANARY'}
        environment = release_scanner.environment(self.root, parent)
        self.assertFalse(any('CANARY' in value for value in environment.values()))
        self.assertEqual(environment['HOME'], str(self.root))
        self.assertEqual(environment['SYFT_CHECK_FOR_APP_UPDATE'], 'false')
        self.program_text('import json,os\nprint(json.dumps(dict(os.environ)))\n')
        raw = release_scanner.capture([str(self.program)], self.root, environment, 65536, 5)
        actual = json.loads(raw)
        self.assertNotIn('GITHUB_TOKEN', actual)
        self.assertNotIn('DATABASE_URL', actual)
        self.assertNotIn('SYFT_REGISTRY_AUTH_PASSWORD', actual)

    def test_process_failure_never_exports_scanner_stderr_or_traceback(self):
        self.program_text('import sys\nprint("SECRET_CANARY /PRIVATE_CANARY",file=sys.stderr)\nraise SystemExit(2)\n')
        with self.assertRaisesRegex(ValueError, '^release scanner failed$') as error:
            release_scanner.capture([str(self.program)], self.root, {}, 1024, 5)
        self.assertNotIn('CANARY', str(error.exception))

    def test_oversized_output_is_stopped_and_rejected(self):
        self.program_text('import sys\nsys.stdout.write("x"*65536)\n')
        with self.assertRaisesRegex(ValueError, '^release scanner failed$'):
            release_scanner.capture([str(self.program)], self.root, {}, 1024, 5)

    def test_stalled_process_is_stopped_and_rejected(self):
        self.program_text('import time\ntime.sleep(30)\n')
        with self.assertRaisesRegex(ValueError, '^release scanner failed$'):
            release_scanner.capture([str(self.program)], self.root, {}, 1024, 0.05)

    def test_container_scan_requires_both_recognized_os_and_go_package_inventories(self):
        subject = {'name': 'ghcr.io/aatuh/evydence:v0.0.0-rc.1403', 'kind': 'container', 'sha256': 'a' * 64}
        go = {'type': 'library', 'name': 'stdlib', 'version': 'go1.27.2', 'purl': 'pkg:golang/stdlib@1.27.2'}
        apk = {'type': 'library', 'name': 'busybox', 'version': '1.37.0-r30',
               'purl': 'pkg:apk/alpine/busybox@1.37.0-r30?arch=x86_64&distro=alpine-3.23.2'}
        for index, components in enumerate([[go], [apk], [go, apk]]):
            with self.subTest(components=components):
                raw = json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': components,
                                  'metadata': {'private': 'SECRET_CANARY /PRIVATE_CANARY'}}).encode()
                with mock.patch.object(release_scanner, 'capture', return_value=raw) as capture:
                    call = lambda: release_scanner.scan_container(self.program, self.root / 'image.oci.tar',
                                                                  subject, self.root / ('scan-' + str(index)))
                    if len(components) < 2:
                        with self.assertRaises(ValueError):
                            call()
                    else:
                        bom = call()
                        self.assertEqual(len(bom['components']), 2)
                        self.assertNotIn('CANARY', json.dumps(bom))
                        self.assertIn('oci-archive:', ' '.join(capture.call_args.args[0]))


if __name__ == '__main__':
    unittest.main()
