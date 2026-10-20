#!/usr/bin/env python3
"""Build an isolated, checksum-pinned Syft tool with the reviewed Go/dependency locks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import release_artifacts
import release_build
import release_evidence_profile as profile
import release_scanner
import release_sbom


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUM = 'h1:IdNS5Ha7WfatXHDL0qzjdf7DBVnfb8OI3FpSbltv0nc='
SOURCE_MOD_SUM = 'h1:M3Nnl7wN05wWBbffETQ+P3TEhuCDuOUhfTD4tyNX4rA='
LOCKS = ('release/tools/syft.go.mod', 'release/tools/syft.go.sum')


def invalid():
    return ValueError('invalid pinned release tool')


def source_directory(record):
    try:
        if (type(record) is not dict or record.get('Version') != 'v' + release_sbom.SYFT_VERSION
                or record.get('Sum') != SOURCE_SUM or record.get('GoModSum') != SOURCE_MOD_SUM
                or type(record.get('Dir')) is not str or '\x00' in record['Dir']
                or not Path(record['Dir']).is_absolute() or record.get('Error')):
            raise invalid()
        return Path(record['Dir'])
    except (TypeError, ValueError):
        raise invalid() from None


def file_digest(path):
    stream, _size = release_artifacts.regular_file(path)
    with stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_installation(directory, recipe_sha):
    try:
        directory = Path(directory)
        if directory.is_symlink() or not directory.is_dir():
            raise invalid()
        stream, size = release_artifacts.regular_file(directory / 'installation.json')
        with stream:
            if size > 4096:
                raise invalid()
            record = profile.parse_json(stream.read(4097))
        if (set(record) != {'schema', 'recipe_sha256', 'binary_sha256'}
                or record['schema'] != 'evydence-release-tool.v1' or record['recipe_sha256'] != recipe_sha
                or not profile.valid_sha(record['binary_sha256'])
                or file_digest(directory / 'syft') != record['binary_sha256']):
            raise invalid()
        return directory / 'syft'
    except (OSError, ValueError, KeyError, TypeError):
        raise invalid() from None


def recipe_digest():
    names = LOCKS + ('scripts/release_evidence_tools.py',)
    values = {name: file_digest(ROOT / name) for name in names}
    values['go_version'] = release_scanner.SCANNER_GO_VERSION
    values['source_sum'] = SOURCE_SUM
    values['source_mod_sum'] = SOURCE_MOD_SUM
    values['source_commit'] = release_scanner.SYFT_SOURCE_COMMIT
    values['source_version'] = release_sbom.SYFT_VERSION
    return profile.digest(profile.json_bytes(values))


def install(output_root):
    output_root = Path(output_root)
    if output_root.is_symlink():
        raise invalid()
    output_root.mkdir(parents=True, exist_ok=True)
    output_root = output_root.resolve()
    recipe = recipe_digest()
    destination = output_root / ('syft-' + release_sbom.SYFT_VERSION + '-' + recipe[:16])
    if destination.exists() or destination.is_symlink():
        return verify_installation(destination, recipe)
    environment = release_build.build_environment(os.environ, release_scanner.SCANNER_GO_VERSION.removeprefix('go'))
    temporary = Path(tempfile.mkdtemp(prefix='.syft-build-', dir=output_root))
    # Preserve an unsuccessful isolated build for diagnosis; never overwrite a
    # completed installation or silently substitute an unqualified binary.
    with (temporary / 'build.log').open('xb') as log:
        bootstrap = temporary / 'bootstrap'
        bootstrap.mkdir(mode=0o700)
        (bootstrap / 'go.mod').write_text(
            'module github.com/aatuh/evydence/release-tool-bootstrap\n\n'
            + 'go ' + release_scanner.SCANNER_GO_VERSION.removeprefix('go') + '\n\n'
            + 'require github.com/anchore/syft v' + release_sbom.SYFT_VERSION + '\n')
        (bootstrap / 'go.sum').write_text(
            'github.com/anchore/syft v' + release_sbom.SYFT_VERSION + ' ' + SOURCE_SUM + '\n'
            + 'github.com/anchore/syft v' + release_sbom.SYFT_VERSION + '/go.mod ' + SOURCE_MOD_SUM + '\n')
        raw = subprocess.check_output(['go', 'mod', 'download', '-json',
                                       'github.com/anchore/syft@v' + release_sbom.SYFT_VERSION],
                                      cwd=bootstrap, env=environment, stderr=log, timeout=300)
        source = source_directory(profile.parse_json(raw))
        # Verify Syft while it is a dependency: once copied as the main module,
        # "go mod verify" only checks its dependencies, not these source bytes.
        subprocess.run(['go', 'mod', 'verify'], cwd=bootstrap, env=environment,
                       stdout=log, stderr=log, check=True, timeout=600)
        working = temporary / 'source'
        shutil.copytree(source, working)
        working.chmod(0o700)
        for directory in working.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o700)
        for lock, name in zip(LOCKS, ('go.mod', 'go.sum')):
            (working / name).chmod(0o600)
            shutil.copyfile(ROOT / lock, working / name)
        compiler = subprocess.check_output(['go', 'env', 'GOVERSION'], cwd=working,
                                          env=environment, stderr=log, timeout=30).decode().strip()
        if compiler != release_scanner.SCANNER_GO_VERSION:
            raise invalid()
        subprocess.run(['go', 'mod', 'verify'], cwd=working, env=environment,
                       stdout=log, stderr=log, check=True, timeout=600)
        output = temporary / 'output'
        output.mkdir(mode=0o700)
        flags = ('-s -w -buildid= -X main.version=' + release_sbom.SYFT_VERSION
                 + ' -X main.gitCommit=' + release_scanner.SYFT_SOURCE_COMMIT
                 + ' -X main.gitDescription=v' + release_sbom.SYFT_VERSION)
        subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-mod=readonly', '-pgo=off',
                        '-ldflags', flags, '-o', str(output / 'syft'), './cmd/syft'],
                       cwd=working, env=environment, stdout=log, stderr=log, check=True, timeout=1800)
        release_scanner.verify_tool(output / 'syft', temporary)
        record = {'schema': 'evydence-release-tool.v1', 'recipe_sha256': recipe,
                  'binary_sha256': file_digest(output / 'syft')}
        (output / 'installation.json').write_bytes(profile.json_bytes(record))
        output.rename(destination)
    shutil.rmtree(temporary)
    return verify_installation(destination, recipe)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output-root')
    mode.add_argument('--verify-executable')
    arguments = parser.parse_args()
    try:
        if arguments.verify_executable:
            candidate = Path(arguments.verify_executable).resolve()
            executable = verify_installation(candidate.parent, recipe_digest())
            if executable != candidate:
                raise invalid()
            with tempfile.TemporaryDirectory(prefix='evydence-release-scanner-preflight-') as temporary:
                release_scanner.verify_tool(executable, Path(temporary))
        else:
            executable = install(arguments.output_root)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, RecursionError):
        print('pinned release scanner installation failed; preserved isolated build logs for review', file=sys.stderr)
        return 2
    if arguments.verify_executable:
        print('pinned release scanner verified')
    else:
        print(executable)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
