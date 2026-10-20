#!/usr/bin/env python3
"""Verify release evidence against the actual archive and extracted binary bytes."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tempfile

import release_artifacts
import release_evidence_profile as profile
import release_subjects


def read_file(path):
    stream, size = release_artifacts.regular_file(path)
    with stream:
        if size > profile.MAX_JSON_BYTES:
            raise profile.invalid()
        data = stream.read(profile.MAX_JSON_BYTES + 1)
    if len(data) != size or len(data) > profile.MAX_JSON_BYTES:
        raise profile.invalid()
    return data


def checksum_records(path, names):
    raw = read_file(path)
    if len(raw) > 64 * 1024:
        raise profile.invalid()
    lines = raw.decode('ascii').splitlines()
    if not 0 < len(lines) <= 256:
        raise profile.invalid()
    result = {}
    for line in lines:
        match = re.fullmatch(r'([a-f0-9]{64}) [ *](' + names + ')', line)
        if match is None or match[2] in result:
            raise profile.invalid()
        result[match[2]] = match[1]
    return result


def verify_checksums(dist):
    dist = Path(dist)
    if dist.is_symlink() or not dist.is_dir():
        raise profile.invalid()
    records = checksum_records(dist / 'SHA256SUMS', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,255}')
    for name, sha in records.items():
        if release_artifacts.material_digest(dist, Path(name)) != 'sha256:' + sha:
            raise profile.invalid()
    openapi = checksum_records(dist / 'openapi.sha256', r'openapi\.yaml')
    if set(openapi) != {'openapi.yaml'} or release_artifacts.material_digest(dist, Path('openapi.yaml')) != 'sha256:' + openapi['openapi.yaml']:
        raise profile.invalid()
    root = Path(__file__).resolve().parents[1]
    migrations = checksum_records(dist / 'migrations.sha256', r'migrations/[A-Za-z0-9][A-Za-z0-9_.-]{0,250}\.sql')
    for name, sha in migrations.items():
        if release_artifacts.material_digest(root, Path(name)) != 'sha256:' + sha:
            raise profile.invalid()


def verify(dist, tag, commit):
    release_artifacts.validate_coordinates(tag, commit)
    dist = Path(dist)
    with tempfile.TemporaryDirectory(prefix='evydence-release-verify-subjects-') as temporary:
        records = release_subjects.collect(dist, tag, Path(temporary) / 'subjects')
        manifest_bytes = read_file(dist / 'release-build-manifest.json')
        manifest = profile.parse_json(manifest_bytes)
        names = {profile.INDEX_NAME, profile.PROVENANCE_NAME, profile.SUMMARY_NAME}
        names.update(profile.sbom_name(item['name']) for item in records)
        documents = {name: read_file(dist / name) for name in sorted(names)}
        profile.verify_documents(documents, records, manifest, profile.digest(manifest_bytes), tag, commit)
    return len(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dist')
    mode.add_argument('--legacy-identity', action='store_true')
    parser.add_argument('--repository', default='aatuh/evydence')
    parser.add_argument('--checksums-only', action='store_true')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args()
    try:
        if args.checksums_only:
            if not args.dist:
                raise profile.invalid()
            release_artifacts.validate_coordinates(args.tag, args.expected_commit)
            verify_checksums(args.dist)
            print('bounded release and migration checksums verified')
            return 0
        if args.legacy_identity:
            policy = Path(__file__).resolve().parents[1] / 'release/legacy-evidence.json'
            profile.verify_legacy_identity(read_file(policy), args.repository, args.tag, args.expected_commit)
            print('legacy release identity allowlisted; artifact SBOM subject verification is unavailable')
            return 0
        count = verify(args.dist, args.tag, args.expected_commit)
    except (OSError, ValueError, UnicodeError, RecursionError):
        print('release evidence subject verification failed', file=sys.stderr)
        return 2
    print('release evidence subjects verified:', count)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
