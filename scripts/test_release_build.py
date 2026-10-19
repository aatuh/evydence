#!/usr/bin/env python3
"""Build orchestration invariants use mocked process reads, never compilation."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_build as builder


class ReleaseBuildTests(unittest.TestCase):
    def test_environment_pins_compiler_inputs_and_excludes_credentials(self):
        parent = dict(os.environ, GH_TOKEN='PRIVATE_SECRET', EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64='PRIVATE_KEY',
                      EVYDENCE_TEST_DATABASE_URL='PRIVATE_DATABASE', GOFLAGS='-tags=PRIVATE',
                      GOEXPERIMENT='PRIVATE', GOAMD64='v4', GOOS='windows', GOARCH='386',
                      GOENV='/PRIVATE_PATH', GOTOOLCHAIN='go1.26.9', GOCACHE='/tmp/cache')
        environment = builder.build_environment(parent, '1.27.2')
        self.assertEqual(environment['GOTOOLCHAIN'], 'go1.27.2')
        self.assertEqual(environment['GOENV'], 'off')
        self.assertEqual(environment['GOWORK'], 'off')
        self.assertEqual(environment['GOFLAGS'], '-p=1')
        self.assertEqual(environment['GOAMD64'], 'v1')
        self.assertEqual(environment['GOEXPERIMENT'], '')
        self.assertEqual(environment['CGO_ENABLED'], '0')
        self.assertEqual(environment['GOCACHE'], '/tmp/cache')
        self.assertNotIn('GOOS', environment)
        self.assertNotIn('GOARCH', environment)
        self.assertFalse(any('PRIVATE' in value for value in environment.values()))

    def test_output_directories_must_be_empty_separate_and_outside_source_ancestors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            root.mkdir()
            (root / 'preserved').write_text('source')
            for output, work in [(root, root / 'work'), (root.parent, root / 'work'),
                                 (root / 'out', root / 'out/work')]:
                with self.subTest(output=output, work=work), self.assertRaises(ValueError):
                    builder.prepare_directories(root, output, work)
            self.assertEqual((root / 'preserved').read_text(), 'source')
            output, work = root / 'dist/tag', root / 'tmp/build'
            builder.prepare_directories(root, output, work)
            self.assertTrue(output.is_dir() and work.is_dir())
            (output / 'preserved').write_text('artifact')
            with self.assertRaises(ValueError):
                builder.prepare_directories(root, output, work)
            self.assertEqual((output / 'preserved').read_text(), 'artifact')

    def test_source_identity_rejects_dirty_changed_or_unreadable_source(self):
        for head, status in [('b' * 40, ''), ('a' * 40, ' M source.go'), ('PRIVATE', '')]:
            with self.subTest(head=head, status=status), mock.patch.object(builder, 'capture', side_effect=[head, status]):
                with self.assertRaises(ValueError):
                    builder.source_identity(Path('/unused'), 'a' * 40, {})
        with mock.patch.object(builder, 'capture', side_effect=['a' * 40, '']):
            self.assertEqual(builder.source_identity(Path('/unused'), 'a' * 40, {}), 'a' * 40)

    def test_invalid_coordinates_stop_before_compiler_or_git_commands(self):
        root = Path(builder.__file__).resolve().parents[1]
        with mock.patch.object(builder, 'source_identity', return_value='a' * 40), \
                mock.patch.object(builder, 'capture', side_effect=['go1.27.2', '1700000000']) as captured:
            with self.assertRaises(ValueError):
                builder.build_release(root, '../PRIVATE', root / 'tmp/unused', root / 'tmp/unused-work', 'a' * 40)
            captured.assert_not_called()


if __name__ == '__main__':
    unittest.main()
