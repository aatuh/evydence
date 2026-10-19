#!/usr/bin/env python3
"""Build or compare complete unsigned release payloads with bounded, sanitized reports."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zlib

import release_artifacts as artifacts
import release_build
import support_matrix


REPORT_SCHEMA = 'evydence.reproducible-build.v1'
REPORT_NAME = 'reproducible-build.json'
MAX_REPORT_BYTES = 2 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]


def artifact_paths(policy, tag):
    artifacts.validate_coordinates(tag, '0' * 40)
    paths = {'work/release-build-manifest.json': 'build-manifest'}
    for target in support_matrix.release_plan(policy):
        directory = 'evydence_' + tag + '_' + target['goos'] + '_' + target['goarch']
        suffix = '.zip' if target['goos'] == 'windows' else '.tar.gz'
        paths['archives/' + directory + suffix] = 'archive'
        for command in target['commands']:
            name = command + ('.exe' if target['goos'] == 'windows' else '')
            paths['work/' + directory + '/' + name] = 'binary'
    return dict(sorted(paths.items()))


def file_record(root, relative, kind):
    path = Path(root)
    if path.is_symlink():
        raise ValueError('invalid artifact bundle')
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('invalid artifact file')
    handle, expected_size = artifacts.regular_file(path)
    digest, count = hashlib.sha256(), 0
    with handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            count += len(chunk)
            if count > artifacts.MAX_FILE_BYTES:
                raise ValueError('invalid artifact size')
            digest.update(chunk)
    if count != expected_size:
        raise ValueError('artifact changed while reading')
    return {'kind': kind, 'bytes': count, 'sha256': digest.hexdigest()}


def artifact_inventory(bundle, policy, tag):
    return {path: file_record(bundle, path, kind) for path, kind in artifact_paths(policy, tag).items()}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate report field')
        result[key] = value
    return result


def read_report(bundle):
    if Path(bundle).is_symlink():
        raise ValueError('invalid artifact bundle')
    handle, size = artifacts.regular_file(Path(bundle) / REPORT_NAME)
    with handle:
        if size > MAX_REPORT_BYTES:
            raise ValueError('oversized artifact report')
        data = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError('oversized artifact report')
    report = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(report, dict):
        raise ValueError('invalid artifact report')
    return report


def compare_bundles(first, second, tag, commit):
    artifacts.validate_coordinates(tag, commit)
    policy = support_matrix.load_policy()
    paths = artifact_paths(policy, tag)
    differences, reports, inventories = [], [], []
    expected = {'schema_version': REPORT_SCHEMA, 'source_commit': commit, 'tag': tag,
                'go_version': 'go' + policy['go']['current'], 'build_recipe_version': artifacts.RECIPE_VERSION}
    for slot, bundle in [('first', first), ('second', second)]:
        try:
            report = read_report(bundle)
        except (OSError, ValueError, UnicodeError, RecursionError):
            report = {}
            differences.append({'control': slot + '_report', 'reason': 'unreadable_or_invalid'})
        reports.append(report)
        for key, value in expected.items():
            if report.get(key) != value:
                differences.append({'control': slot + '_' + key, 'reason': 'mismatch'})
        epoch = report.get('source_date_epoch')
        if type(epoch) is not int or not 0 <= epoch < 2**32:
            differences.append({'control': slot + '_source_date_epoch', 'reason': 'invalid'})
        records = report.get('artifacts')
        if not isinstance(records, dict) or set(records) != set(paths):
            differences.append({'control': slot + '_artifact_set', 'reason': 'incomplete_or_unexpected'})
            records = {}
        inventory = {}
        for path, kind in paths.items():
            record = records.get(path)
            if (not isinstance(record, dict) or record.get('kind') != kind
                    or type(record.get('bytes')) is not int or not 0 <= record['bytes'] <= artifacts.MAX_FILE_BYTES
                    or not isinstance(record.get('sha256'), str)
                    or re.fullmatch(r'[a-f0-9]{64}', record['sha256']) is None):
                differences.append({'artifact': path, 'reason': slot + '_record_invalid'})
                continue
            try:
                actual = file_record(bundle, path, kind)
            except (OSError, ValueError):
                differences.append({'artifact': path, 'reason': slot + '_bytes_unreadable'})
                continue
            if actual != record:
                differences.append({'artifact': path, 'reason': slot + '_report_does_not_match_bytes'})
                continue
            inventory[path] = actual
        inventories.append(inventory)
    if reports[0].get('source_date_epoch') != reports[1].get('source_date_epoch'):
        differences.append({'control': 'source_date_epoch', 'reason': 'mismatch'})
    compared = 0
    for path in paths:
        if path in inventories[0] and path in inventories[1]:
            compared += 1
            if inventories[0][path] != inventories[1][path]:
                differences.append({'artifact': path, 'reason': 'artifact_bytes_differ'})
    return {'schema_version': 'evydence.reproducible-comparison.v1', 'scope': 'artifact-byte-equality',
            'source_commit': commit, 'tag': tag, 'passed': not differences,
            'artifact_count': compared, 'expected_artifact_count': len(paths), 'differences': differences,
            'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'limitations': ['Artifact equality does not independently authenticate runner identities or artifact provenance.']}


def build_bundle(root, bundle, tag, commit, *, environment=None):
    bundle = Path(bundle)
    if bundle.is_symlink() or bundle.exists() and (not bundle.is_dir() or any(bundle.iterdir())):
        raise ValueError('artifact bundle must be empty')
    manifest = release_build.build_release(root, tag, bundle / 'archives', bundle / 'work', commit,
                                          parent_environment=environment)
    report = {'schema_version': REPORT_SCHEMA, 'source_commit': commit, 'tag': tag,
              'go_version': manifest['go_version'], 'source_date_epoch': manifest['source_date_epoch'],
              'build_recipe_version': manifest['build_recipe_version'],
              'tool_versions': {'python': platform.python_version(), 'zlib': zlib.ZLIB_RUNTIME_VERSION},
              'artifacts': artifact_inventory(bundle, support_matrix.load_policy(root), tag)}
    with (bundle / REPORT_NAME).open('x', encoding='utf-8') as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def repeat_builds(root, output_root, tag, commit):
    environment = release_build.build_environment(os.environ, support_matrix.load_policy(root)['go']['current'])
    release_build.source_identity(root, commit, environment)
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='run-', dir=output_root)).resolve()
    for slot in ['first', 'second']:
        source = run / ('source-' + slot)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(source), commit], cwd=root,
                       env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        parent = dict(os.environ, GOCACHE=str(run / ('cache-' + slot)))
        print('Building local repeatability slot ' + slot, file=sys.stderr, flush=True)
        build_bundle(source, run / slot, tag, commit, environment=parent)
        release_build.source_identity(source, commit, environment)
        # No force: unexpected local edits preserve the owned worktree for review.
        subprocess.run(['git', 'worktree', 'remove', str(source)], cwd=root,
                       env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    release_build.source_identity(root, commit, environment)
    result = compare_bundles(run / 'first', run / 'second', tag, commit)
    result['execution_scope'] = 'two-local-worktrees-with-separate-build-caches'
    with (run / 'comparison.json').open('x', encoding='utf-8') as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print('Local repeatability evidence: ' + str(run), file=sys.stderr, flush=True)
    return result


def main(argv=None):
    parser = artifacts.Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--bundle', required=True, type=Path)
    compare = commands.add_parser('compare')
    compare.add_argument('--first', required=True, type=Path)
    compare.add_argument('--second', required=True, type=Path)
    compare.add_argument('--output', type=Path)
    repeat = commands.add_parser('repeat')
    repeat.add_argument('--output-root', required=True, type=Path)
    for command in [build, compare, repeat]:
        command.add_argument('--tag', required=True)
        command.add_argument('--expected-commit', required=True)
    args = parser.parse_args(argv)
    try:
        artifacts.validate_coordinates(args.tag, args.expected_commit)
        if args.command == 'build':
            build_bundle(ROOT, args.bundle, args.tag, args.expected_commit)
            return 0
        if args.command == 'compare':
            result = compare_bundles(args.first, args.second, args.tag, args.expected_commit)
            if args.output:
                with args.output.open('x', encoding='utf-8') as output:
                    output.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
        else:
            result = repeat_builds(ROOT, args.output_root, args.tag, args.expected_commit)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result['passed'] else 1
    except (OSError, ValueError, subprocess.SubprocessError, support_matrix.PolicyError):
        print('reproducible build inputs, source, or execution are invalid', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
