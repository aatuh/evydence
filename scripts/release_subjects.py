#!/usr/bin/env python3
"""Read the supported release payloads without trusting archive paths or links."""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import tarfile
import zipfile

import release_artifacts as artifacts
import support_matrix


MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 16


def invalid():
    return ValueError('invalid release subject payload')


def digest(stream, expected_size, destination=None):
    value, size = hashlib.sha256(), 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        if size > expected_size or size > MAX_EXPANDED_BYTES:
            raise invalid()
        value.update(chunk)
        if destination is not None:
            destination.write(chunk)
    if size != expected_size:
        raise invalid()
    return value.hexdigest()


def collect(dist, tag, scratch):
    """Return private working paths and public identities; never extract documents."""
    try:
        artifacts.validate_coordinates(tag, '0' * 40)
        dist, scratch = Path(dist), Path(scratch)
        if dist.is_symlink() or not dist.is_dir() or scratch.exists() or scratch.is_symlink():
            raise invalid()
        scratch.mkdir(mode=0o700)
        records = []
        for target in support_matrix.release_plan(support_matrix.load_policy()):
            directory = f"evydence_{tag}_{target['goos']}_{target['goarch']}"
            commands = {command + ('.exe' if target['goos'] == 'windows' else '')
                        for command in target['commands']}
            expected = {directory + '/' + name for name in commands | artifacts.DOCUMENTS}
            suffix = '.zip' if target['goos'] == 'windows' else '.tar.gz'
            path = dist / (directory + suffix)
            handle, size = artifacts.regular_file(path)
            with handle:
                if size > MAX_EXPANDED_BYTES:
                    raise invalid()
                archive_digest = digest(handle, size)
                handle.seek(0)
                records.append({'name': path.name, 'kind': 'archive', 'sha256': archive_digest,
                                'bytes': size, 'path': path})
                archive = (zipfile.ZipFile(handle) if suffix == '.zip'
                           else tarfile.open(fileobj=handle, mode='r:gz'))
                with archive:
                    seen, expanded = set(), 0
                    members = archive.infolist() if suffix == '.zip' else archive
                    for member in members:
                        name = member.filename if suffix == '.zip' else member.name
                        is_directory = member.is_dir() if suffix == '.zip' else member.isdir()
                        # Both normalized formats include one canonical directory entry.
                        if is_directory and name.rstrip('/') == directory:
                            if directory in seen or (member.file_size if suffix == '.zip' else member.size) != 0:
                                raise invalid()
                            seen.add(directory)
                            continue
                        if name not in expected or name in seen or len(seen) >= MAX_ENTRIES:
                            raise invalid()
                        seen.add(name)
                        if suffix == '.zip':
                            mode = member.external_attr >> 16
                            if (member.flag_bits & 1 or member.is_dir()
                                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                                raise invalid()
                            member_size = member.file_size
                            stream = archive.open(member)
                        else:
                            if not member.isfile() or member.issparse():
                                raise invalid()
                            member_size = member.size
                            stream = archive.extractfile(member)
                        expanded += member_size
                        if not 0 <= expanded <= MAX_EXPANDED_BYTES or stream is None:
                            if stream is not None:
                                stream.close()
                            raise invalid()
                        binary = name.rsplit('/', 1)[1] in commands
                        with stream:
                            if binary:
                                output = scratch / name.replace('/', '__')
                                with output.open('xb') as destination:
                                    actual = digest(stream, member_size, destination)
                                records.append({'name': name, 'kind': 'binary', 'sha256': actual,
                                                'bytes': member_size, 'path': output})
                            else:
                                digest(stream, member_size)
                    if seen - {directory} != expected:
                        raise invalid()
        return sorted(records, key=lambda item: item['name'])
    except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
        raise invalid() from None
