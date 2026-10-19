#!/usr/bin/env python3
"""Create source-relative release identities and normalized archive bytes."""
from __future__ import annotations

import contextlib
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import zipfile


RECIPE_VERSION = 'evydence-release-build.v1'
BUILD_MATERIALS = (
    'Dockerfile', 'go.mod', 'go.sum', 'openapi.yaml',
    'release/support-matrix.json', 'scripts/build_ldflags.sh',
    'scripts/release_candidate_package.sh', 'scripts/release_artifacts.py', 'scripts/release_build.py',
)
DOCUMENTS = {'LICENSE', 'README.md', 'CHANGELOG.md'}
MAX_FILE_BYTES = 1024 * 1024 * 1024


def checked_epoch(epoch):
    if type(epoch) is not int or not 0 <= epoch < 2**32:
        raise ValueError('invalid release source timestamp')
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)


def regular_file(path):
    """Open one regular file without following its final symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        handle = os.fdopen(descriptor, 'rb')
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            handle.close()
            raise ValueError('invalid release input file')
        return handle, info.st_size
    except OSError:
        raise ValueError('invalid release input file') from None


def material_digest(root, relative):
    if relative.is_absolute() or any(part in {'.', '..'} for part in relative.parts):
        raise ValueError('invalid release material path')
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('invalid release material path')
    digest = hashlib.sha256()
    handle, _ = regular_file(path)
    with handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return 'sha256:' + digest.hexdigest()


def validate_coordinates(tag, commit):
    if (not isinstance(tag, str) or re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+', tag) is None
            or not isinstance(commit, str) or re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', commit) is None):
        raise ValueError('invalid release build identity')


def build_manifest(root, *, tag, commit, epoch, go_version):
    validate_coordinates(tag, commit)
    timestamp = checked_epoch(epoch)
    if not isinstance(go_version, str) or re.fullmatch(r'go1\.[0-9]+\.[0-9]+', go_version) is None:
        raise ValueError('invalid release compiler identity')
    root = Path(root)
    if root.is_symlink() or (root / 'migrations').is_symlink() or not (root / 'migrations').is_dir():
        raise ValueError('invalid release source directory')
    names = set(BUILD_MATERIALS)
    for path in (root / 'migrations').rglob('*'):
        if path.is_symlink():
            raise ValueError('invalid release material path')
        if path.is_file():
            names.add(path.relative_to(root).as_posix())
    materials = [{'path': name, 'digest': material_digest(root, Path(name))} for name in sorted(names)]
    return {
        'schema_version': 'evydence-release-build-manifest.v1',
        'build_recipe_version': RECIPE_VERSION,
        'tag': tag, 'commit': commit, 'go_version': go_version,
        'source_date_epoch': epoch,
        'build_time': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'materials': materials,
        'limitations': [
            'Source commit time is the fixed build identity time, not a measurement of execution time.',
            'This pre-build manifest identifies source and recipe inputs; the final signed manifest covers artifact bytes.',
            'It is not a certification, legal compliance conclusion, or secure-release guarantee.',
        ],
    }


def safe_name(value):
    return (isinstance(value, str) and value not in {'.', '..'}
            and re.fullmatch(r'[A-Za-z0-9_.-]+', value) is not None)


def write_archive(directory, output, epoch, executables):
    timestamp = checked_epoch(epoch)
    directory, output = Path(directory), Path(output)
    if (not isinstance(executables, list) or not 1 <= len(executables) <= 16
            or not all(safe_name(name) for name in executables)
            or len(set(executables)) != len(executables) or DOCUMENTS.intersection(executables)):
        raise ValueError('invalid release executable names')
    if directory.is_symlink() or not directory.is_dir() or not safe_name(directory.name):
        raise ValueError('invalid release archive directory')
    if output.exists() or output.is_symlink():
        raise ValueError('release archive output already exists')
    if output.resolve().is_relative_to(directory.resolve()):
        raise ValueError('release archive output must be outside its payload')
    is_zip = output.name.endswith('.zip')
    if not is_zip and not output.name.endswith('.tar.gz'):
        raise ValueError('unsupported release archive format')
    names = DOCUMENTS.union(executables)
    if {p.name for p in directory.iterdir()} != names:
        raise ValueError('release archive payload does not match the allowlist')
    created, completed = False, False
    try:
        with contextlib.ExitStack() as stack:
            files = {}
            for name in sorted(names):
                handle, size = regular_file(directory / name)
                files[name] = (stack.enter_context(handle), size)
            target = stack.enter_context(output.open('xb'))
            created = True
            entries = [(directory.name + '/', None, 0)] + [
                (directory.name + '/' + name, name, files[name][1]) for name in sorted(names)]
            if is_zip:
                # Stored entries avoid compressor-version variance for Windows.
                date = max(timestamp, datetime.datetime(1980, 1, 1, tzinfo=datetime.timezone.utc))
                with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED) as archive:
                    for member, name, size in entries:
                        info = zipfile.ZipInfo(member, date.timetuple()[:6])
                        info.create_system = 3
                        mode = 0o755 if name is None or name in executables else 0o644
                        kind = stat.S_IFDIR if name is None else stat.S_IFREG
                        info.external_attr = (kind | mode) << 16
                        if name is None:
                            info.external_attr |= 0x10
                        info.file_size = size
                        with archive.open(info, 'w') as destination:
                            if name is not None:
                                shutil.copyfileobj(files[name][0], destination, 1024 * 1024)
            else:
                with gzip.GzipFile(filename='', fileobj=target, mode='wb', mtime=epoch, compresslevel=9) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                        for member, name, size in entries:
                            info = tarfile.TarInfo(member)
                            info.type = tarfile.DIRTYPE if name is None else tarfile.REGTYPE
                            info.mode = 0o755 if name is None or name in executables else 0o644
                            info.mtime, info.size = epoch, size
                            archive.addfile(info, None if name is None else files[name][0])
        completed = True
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        raise ValueError('release archive could not be written') from None
    finally:
        if created and not completed:
            output.unlink(missing_ok=True)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, 'invalid release artifact arguments\n')


def main(argv=None):
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    manifest = commands.add_parser('manifest')
    manifest.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    manifest.add_argument('--tag', required=True)
    manifest.add_argument('--commit', required=True)
    manifest.add_argument('--go-version', required=True)
    archive = commands.add_parser('archive')
    archive.add_argument('--directory', type=Path, required=True)
    archive.add_argument('--executable', action='append', required=True)
    for command in [manifest, archive]:
        command.add_argument('--epoch', type=int, required=True)
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'manifest':
            data = build_manifest(args.root, tag=args.tag, commit=args.commit, epoch=args.epoch,
                                  go_version=args.go_version)
            with args.output.open('x', encoding='utf-8') as output:
                output.write(json.dumps(data, indent=2, sort_keys=True) + '\n')
        else:
            write_archive(args.directory, args.output, args.epoch, args.executable)
    except (OSError, ValueError):
        print('release artifact inputs or output are invalid', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
