"""Bounded synthetic/public properties; no publication, provider or execution."""
import argparse
import copy
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from unittest import mock
import warnings
import zipfile
import zlib

import paired_backup_manifest as paired
import release_artifacts
import release_evidence_profile as profile
import release_evidence_verify as evidence_verify
import release_sbom
import release_signing
import release_subjects
import support_matrix

ROOT = Path(__file__).resolve().parents[1]
TAG, COMMIT = 'v0.0.0-rc.1111', 'a' * 40


def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('controlled invalid input acquired an accepted interpretation')


def observe(call):
    try:
        return True, call()
    except ValueError as error:
        return False, str(error)


def same_json(left, right):
    # Parsed input is byte-bounded. Walk its values iteratively so the oracle's
    # comparison recursion limit cannot masquerade as an owner failure.
    pending = [(left, right)]
    while pending:
        left, right = pending.pop()
        if type(left) is not type(right):
            return False
        if type(left) is dict:
            if left.keys() != right.keys():
                return False
            pending.extend((value, right[key]) for key, value in left.items())
        elif type(left) is list:
            if len(left) != len(right):
                return False
            pending.extend(zip(left, right))
        elif left != right:
            return False
    return True


def fixture_manifest():
    return {'schema_version': 'evydence-release-build-manifest.v1',
            'build_recipe_version': release_artifacts.RECIPE_VERSION, 'tag': TAG, 'commit': COMMIT,
            'go_version': 'go' + support_matrix.load_policy()['go']['current'],
            'materials': [{'path': 'go.mod', 'digest': 'sha256:' + 'b' * 64}]}


def fixture_components():
    return [{'type': 'library', 'name': 'example.com/synthetic', 'version': 'v1.0.0',
             'purl': 'pkg:golang/example.com/synthetic@v1.0.0'}]


def evidence(raw, mode):
    first, value = observe(lambda: profile.parse_json(raw))
    again, repeated = observe(lambda: profile.parse_json(raw))
    assert first == again and same_json(value, repeated)
    records = [{'name': 'evydence_linux_amd64/evydence', 'kind': 'binary',
                'sha256': hashlib.sha256(b'synthetic binary').hexdigest(), 'bytes': 16}]
    manifest = fixture_manifest()
    boms = {r['name']: release_sbom.bound_bom(r, fixture_components()) for r in records}
    documents = profile.documents(records, boms, manifest, 'c' * 64, TAG, COMMIT, invocation='local')
    before = copy.deepcopy((documents, records, manifest))

    def verify(values):
        profile.verify_documents(values, records, manifest, 'c' * 64, TAG, COMMIT)

    verify(documents)
    verify(documents)
    selected = [profile.PROVENANCE_NAME, profile.INDEX_NAME, profile.SUMMARY_NAME][mode % 3]
    generated = dict(documents, **{selected: raw})
    accepted, result = observe(lambda: verify(generated))
    assert (accepted, result) == observe(lambda: verify(generated))
    if accepted:
        assert generated == documents
    changed = copy.deepcopy(documents)
    if mode % 4 == 0:
        value = json.loads(changed[profile.PROVENANCE_NAME])
        value['subject'][0]['digest']['sha256'] = '0' * 64
        changed[profile.PROVENANCE_NAME] = profile.json_bytes(value)
    elif mode % 4 == 1:
        del changed[profile.sbom_name(records[0]['name'])]
    elif mode % 4 == 2:
        value = json.loads(changed[profile.INDEX_NAME])
        value['unknown'] = True
        changed[profile.INDEX_NAME] = profile.json_bytes(value)
    else:
        changed[profile.SUMMARY_NAME] += b' '
    rejects(lambda: verify(changed))
    legacy = (ROOT / 'release/legacy-evidence.json').read_bytes()
    policy = profile.parse_json(legacy)
    entry = policy['releases'][0]
    profile.verify_legacy_identity(legacy, entry['repository'], entry['tag'], entry['source_commit'])
    rejects(lambda: profile.verify_legacy_identity(legacy, 'synthetic/foreign', entry['tag'], entry['source_commit']))
    assert (documents, records, manifest) == before
    return accepted, documents[selected]


def checksums(raw, mode):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        record = root / 'records'
        record.write_bytes(raw)
        names = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,40}'
        accepted, result = observe(lambda: evidence_verify.checksum_records(record, names))
        assert (accepted, result) == observe(lambda: evidence_verify.checksum_records(record, names))
        if accepted:
            assert result and all(re.fullmatch(names, name) and re.fullmatch(r'[a-f0-9]{64}', sha)
                                  for name, sha in result.items())
            record.write_text(''.join(sha + '  ' + name + '\n' for name, sha in result.items()))
            assert evidence_verify.checksum_records(record, names) == result
        artifact = root / 'artifact'
        artifact.write_bytes(b'synthetic artifact')
        openapi = root / 'openapi.yaml'
        openapi.write_bytes(b'synthetic OpenAPI bytes')
        migration = sorted((ROOT / 'migrations').glob('*.sql'))[0]
        baseline = hashlib.sha256(artifact.read_bytes()).hexdigest() + '  artifact\n'
        (root / 'SHA256SUMS').write_text(baseline)
        (root / 'openapi.sha256').write_text(hashlib.sha256(openapi.read_bytes()).hexdigest() + '  openapi.yaml\n')
        (root / 'migrations.sha256').write_text(hashlib.sha256(migration.read_bytes()).hexdigest()
                                               + '  migrations/' + migration.name + '\n')
        evidence_verify.verify_checksums(root)
        evidence_verify.verify_checksums(root)
        if mode % 8 == 0:
            artifact.write_bytes(b'changed synthetic artifact')
        elif mode % 8 == 1:
            (root / 'SHA256SUMS').write_text('0' * 64 + '  artifact\n')
        elif mode % 8 == 2:
            artifact.unlink()
            artifact.symlink_to(openapi)
        elif mode % 8 == 3:
            (root / 'SHA256SUMS').write_text('0' * 64 + '  ../synthetic-outside\n')
        elif mode % 8 == 4:
            (root / 'SHA256SUMS').write_text(baseline * 2)
        elif mode % 8 == 5:
            (root / 'openapi.sha256').write_text('0' * 64 + '  openapi.yaml\n')
        elif mode % 8 == 6:
            (root / 'migrations.sha256').write_text('0' * 64 + '  migrations/' + migration.name + '\n')
        else:
            sums = root / 'SHA256SUMS'
            sums.unlink()
            sums.symlink_to(record)
        rejects(lambda: evidence_verify.verify_checksums(root))
        return accepted, baseline.encode()


def backup(raw, mode):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        database = root / 'database.dump'
        database.write_bytes(b'synthetic database backup')
        objects = root / 'objects'
        objects.mkdir()
        (objects / 'payload').write_bytes(b'synthetic evidence object')
        migrations = root / 'migrations'
        migrations.mkdir()
        (migrations / '001.up.sql').write_bytes(b'-- synthetic migration bytes, never executed\n')
        manifest = paired.build_manifest(database, objects, migrations, COMMIT, 'synthetic_checkpoint', 'sha256:' + 'b' * 64)
        before = copy.deepcopy(manifest)
        assert paired.verify_manifest(manifest, database, objects, migrations, COMMIT) == []
        assert paired.verify_manifest(manifest, database, objects, migrations, COMMIT) == []
        path = root / 'manifest.json'
        path.write_bytes(raw)
        args = argparse.Namespace(command='verify', manifest=path, database_dump=database,
                                  objects_dir=objects, migrations_dir=migrations, release_commit=COMMIT)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(paired, 'arguments', return_value=args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = paired.main()
        assert code in (0, 2)
        accepted = code == 0
        if accepted:
            value = json.loads(raw)
            assert value['database'] == manifest['database'] and value['objects'] == manifest['objects']
            assert value['schema'] == manifest['schema'] and value['release_commit'] == COMMIT
        assert 'Traceback' not in stdout.getvalue() + stderr.getvalue()
        changed = copy.deepcopy(manifest)
        if mode % 8 == 0:
            database.write_bytes(b'changed synthetic database')
        elif mode % 8 == 1:
            (objects / 'payload').write_bytes(b'changed synthetic object')
        elif mode % 8 == 2:
            (migrations / '001.up.sql').write_bytes(b'changed migration bytes')
        elif mode % 8 == 3:
            changed['release_commit'] = 'c' * 40
        elif mode % 8 == 4:
            changed['generation_id'] = 'sha256:' + '0' * 64
        elif mode % 8 == 5:
            changed['database']['bytes'] += 1
        elif mode % 8 == 6:
            changed['objects']['inventory_sha256'] = 'sha256:' + '0' * 64
        else:
            changed['consistency_checkpoint']['id'] += '-changed'
        assert paired.verify_manifest(changed, database, objects, migrations, COMMIT)
        assert manifest == before
        return accepted, paired.canonical_json(manifest)


def archive_within_budget(raw, zipped):
    try:
        if zipped:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = archive.infolist()
                return (len(members) <= 32 and sum(m.file_size for m in members) <= 128 * 1024
                        and all(m.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                                and 0 <= m.file_size <= 128 * 1024 for m in members))
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            expanded = compressed.read(128 * 1024 + 1)
        if len(expanded) > 128 * 1024:
            return False
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            count, total = 0, 0
            for member in archive:
                count += 1
                total += member.size
                if count > 32 or member.size < 0 or total > 128 * 1024:
                    return False
        return True
    except (OSError, EOFError, ValueError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, zlib.error):
        # Format corruption is safe to submit to the owner within this byte
        # budget. Only observed/declared excess above excludes an input; the
        # owner must still reject malformed streams through its real contract.
        return True


def archive_records(records):
    result = {}
    for row in records:
        data = row['path'].read_bytes()
        assert hashlib.sha256(data).hexdigest() == row['sha256'] and len(data) == row['bytes']
        assert row['name'] not in result
        result[row['name']] = row['sha256']
    return result


def archives(raw, mode):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        dist = root / 'dist'
        dist.mkdir()
        expected, sources = {}, {}
        for target in support_matrix.release_plan(support_matrix.load_policy()):
            name = f"evydence_{TAG}_{target['goos']}_{target['goarch']}"
            layout = root / name
            layout.mkdir()
            commands = []
            for command in target['commands']:
                binary = command + ('.exe' if target['goos'] == 'windows' else '')
                data = ('synthetic binary:' + name + '/' + binary).encode()
                (layout / binary).write_bytes(data)
                commands.append(binary)
                expected[name + '/' + binary] = hashlib.sha256(data).hexdigest()
            for document in release_artifacts.DOCUMENTS:
                (layout / document).write_bytes(b'synthetic public document\n')
            suffix = '.zip' if target['goos'] == 'windows' else '.tar.gz'
            output = dist / (name + suffix)
            release_artifacts.write_archive(layout, output, 1700000000, commands)
            sources[output] = output.read_bytes()
            expected[output.name] = hashlib.sha256(sources[output]).hexdigest()
        records = release_subjects.collect(dist, TAG, root / 'positive')
        assert archive_records(records) == expected
        assert archive_records(release_subjects.collect(dist, TAG, root / 'repeated')) == expected
        assert all(path.read_bytes() == value for path, value in sources.items())
        manifest = fixture_manifest()
        manifest_bytes = profile.json_bytes(manifest)
        boms = {r['name']: release_sbom.bound_bom(r, fixture_components()) for r in records}
        documents = profile.documents(records, boms, manifest, profile.digest(manifest_bytes), TAG, COMMIT,
                                      invocation='local')
        (dist / 'release-build-manifest.json').write_bytes(manifest_bytes)
        for name, document in documents.items():
            (dist / name).write_bytes(document)
        assert evidence_verify.verify(dist, TAG, COMMIT) == len(expected)
        assert evidence_verify.verify(dist, TAG, COMMIT) == len(expected)
        zipped = bool(mode % 2)
        path = next(p for p in sources if (p.suffix == '.zip') == zipped)
        seed = sources[path]
        accepted = False
        if archive_within_budget(raw, zipped):
            path.write_bytes(raw)
            accepted, result = observe(lambda: release_subjects.collect(dist, TAG, root / 'generated'))
            if accepted:
                assert set(archive_records(result)) == set(expected)
                if hashlib.sha256(raw).hexdigest() != expected[path.name]:
                    rejects(lambda: evidence_verify.verify(dist, TAG, COMMIT))
                else:
                    assert evidence_verify.verify(dist, TAG, COMMIT) == len(expected)
            assert path.read_bytes() == raw
            path.write_bytes(seed)
        attacked_zip = mode % 8 >= 5
        path = next(p for p in sources if (p.suffix == '.zip') == attacked_zip)
        directory = path.name.removesuffix('.zip' if attacked_zip else '.tar.gz')
        binary = directory + '/evydence' + ('.exe' if attacked_zip else '')
        if attacked_zip:
            with warnings.catch_warnings(), zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
                warnings.simplefilter('ignore', UserWarning)
                member = zipfile.ZipInfo('../synthetic-outside' if mode % 8 == 5 else binary)
                if mode % 8 == 7:
                    member.create_system = 3
                    member.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(member, b'x')
                if mode % 8 == 6:
                    archive.writestr(member, b'x')
        else:
            with tarfile.open(path, 'w:gz') as archive:
                member = tarfile.TarInfo('../synthetic-outside' if mode % 8 == 0 else binary)
                member.size = 1
                if mode % 8 == 2:
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '../synthetic-outside', 0
                if mode % 8 == 4:
                    member.size = release_subjects.MAX_EXPANDED_BYTES + 1
                    archive.fileobj.write(member.tobuf())
                    archive.offset += tarfile.BLOCKSIZE
                elif mode % 8 != 3:
                    archive.addfile(member, io.BytesIO(b'x'))
                    if mode % 8 == 1:
                        archive.addfile(member, io.BytesIO(b'x'))
        rejects(lambda: release_subjects.collect(dist, TAG, root / 'controlled-invalid'))
        assert not (root / 'synthetic-outside').exists()
        return accepted, seed


def signing(raw, mode):
    policy = release_signing.load_policy()
    before = copy.deepcopy(policy)
    release_signing.validate_policy(policy)
    kind = 'container' if mode % 2 else 'release'
    identity = release_signing.identity(policy, kind)
    environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                   'GITHUB_REPOSITORY': policy['repository'], 'GITHUB_REF': policy['ref'],
                   'GITHUB_REF_TYPE': 'branch', 'GITHUB_REF_PROTECTED': 'true',
                   'GITHUB_SHA': COMMIT, 'GITHUB_WORKFLOW_SHA': COMMIT,
                   'GITHUB_WORKFLOW_REF': identity.removeprefix('https://github.com/')}
    release_signing.validate_context(policy, kind, environment, COMMIT)
    fields = ['GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'GITHUB_REPOSITORY', 'GITHUB_REF',
              'GITHUB_REF_TYPE', 'GITHUB_REF_PROTECTED', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA']
    changed = dict(environment, **{fields[mode % len(fields)]: 'changed'})
    rejects(lambda: release_signing.validate_context(policy, kind, changed, COMMIT))
    arguments = release_signing.attestation_arguments(policy, kind, Path('artifact'), Path('bundle'), COMMIT)
    for flag, value in [('--cert-identity', identity), ('--cert-oidc-issuer', policy['issuer']),
                        ('--source-ref', policy['ref']), ('--source-digest', COMMIT), ('--signer-digest', COMMIT)]:
        assert arguments[arguments.index(flag) + 1] == value
    assert '--deny-self-hosted-runners' in arguments
    fields = ['schema', 'repository', 'issuer', 'ref', 'environment', 'reviewer', 'workflows', 'legacy']
    invalid_policy = copy.deepcopy(policy)
    invalid_policy[fields[mode % len(fields)]] = None
    rejects(lambda: release_signing.validate_policy(invalid_policy))
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        artifact = root / 'artifact.tar.gz'
        data = b'synthetic artifact bytes, never executed'
        artifact.write_bytes(data)
        manifest = {'schema_version': 'evydence-release-artifacts.v1.0.0', 'generated_at': 'synthetic',
                    'artifacts': [{'path': artifact.name, 'digest': 'sha256:' + hashlib.sha256(data).hexdigest(), 'size': len(data)}]}
        manifest_bytes = profile.json_bytes(manifest)
        manifest_path = root / release_signing.MANIFEST_NAME
        manifest_path.write_bytes(manifest_bytes)
        assert release_signing.verify_manifest_files(root) == {artifact.name}
        if mode % 2:
            manifest_path.write_bytes(raw)
            accepted, result = observe(lambda: release_signing.verify_manifest_files(root))
            assert (accepted, result) == observe(lambda: release_signing.verify_manifest_files(root))
            if accepted:
                assert result == {artifact.name}
            manifest_path.write_bytes(manifest_bytes)
            seed = manifest_bytes
        else:
            accepted, result = observe(lambda: release_signing.validate_policy(profile.parse_json(raw)))
            assert (accepted, result) == observe(lambda: release_signing.validate_policy(profile.parse_json(raw)))
            if accepted:
                assert release_signing.identity(result, kind) == identity
            seed = profile.json_bytes(policy)
        artifact.write_bytes(data + b'changed')
        rejects(lambda: release_signing.verify_manifest_files(root))
        fixture = ROOT / 'scripts/testdata/release-legacy-v0.1.0-rc.7'
        for name in (release_signing.MANIFEST_NAME, release_signing.SIGNATURE_NAME):
            shutil.copyfile(fixture / name, root / name)
        legacy = policy['legacy'][0]
        release_signing.verify_legacy(policy, root, legacy['tag'], legacy['source_commit'])
        original = manifest_path.read_bytes()
        manifest_path.write_bytes(original + b' ')
        rejects(lambda: release_signing.verify_legacy(policy, root, legacy['tag'], legacy['source_commit']))
        manifest_path.write_bytes(original)
        changed = copy.deepcopy(policy)
        changed['legacy'][0]['public_key_sha256'] = '0' * 64
        rejects(lambda: release_signing.verify_legacy(changed, root, legacy['tag'], legacy['source_commit']))
    assert policy == before
    # Context/argv/legacy pins are offline consistency checks. No gh command,
    # provider observation, publisher credential or signature trust is supplied.
    return accepted, seed


def public_release_binding(raw, mode):
    policy = release_signing.load_policy()
    original_policy = copy.deepcopy(policy)
    legacy = policy['legacy'][0]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / 'dist'
        root.mkdir()
        archive_name = 'evydence_' + legacy['tag'] + '_linux_amd64.tar.gz'
        archive = b'synthetic release bytes, never executed'
        files = {archive_name: archive,
                 'SHA256SUMS': (hashlib.sha256(archive).hexdigest() + '  ' + archive_name + '\n').encode()}
        records = []
        for name, data in files.items():
            records.append({'path': name, 'digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
                            'size': len(data)})
        manifest = {'schema_version': 'evydence-release-artifacts.v1.0.0',
                    'generated_at': 'synthetic', 'artifacts': records}
        seed = profile.json_bytes(manifest)
        files[release_signing.MANIFEST_NAME] = seed
        fixture = ROOT / 'scripts/testdata/release-legacy-v0.1.0-rc.7'
        files[release_signing.SIGNATURE_NAME] = (fixture / release_signing.SIGNATURE_NAME).read_bytes()
        for name, data in files.items():
            (root / name).write_bytes(data)
        # This is an explicitly synthetic local pin, not the published legacy
        # trust policy. The real owner verifies file/pin consistency only;
        # signature verification is exercised separately and is not asserted here.
        pinned = copy.deepcopy(policy)
        pinned['legacy'][0]['manifest_sha256'] = hashlib.sha256(seed).hexdigest()
        release_signing.validate_policy(pinned)

        def snapshot():
            return {path.name: path.read_bytes() for path in root.iterdir()}

        def verify(candidate=pinned, repository=policy['repository'], directory=root):
            before = snapshot()
            before_policy = copy.deepcopy(candidate)
            try:
                release_signing.verify_public(candidate, directory, repository, legacy['tag'],
                                              legacy['source_commit'], legacy=True)
            finally:
                assert snapshot() == before and candidate == before_policy

        verify()
        verify()
        (root / release_signing.MANIFEST_NAME).write_bytes(raw)
        accepted, result = observe(verify)
        assert (accepted, result) == observe(verify)
        if accepted:
            assert raw == seed
        (root / release_signing.MANIFEST_NAME).write_bytes(seed)
        if mode % 8 == 0:
            rejects(lambda: verify(repository='synthetic/foreign'))
        elif mode % 8 == 1:
            revoked = copy.deepcopy(pinned)
            revoked['revoked_sources'].append(legacy['source_commit'])
            rejects(lambda: verify(candidate=revoked))
        elif mode % 8 == 2:
            incomplete = copy.deepcopy(manifest)
            incomplete['artifacts'] = [item for item in records if item['path'] != 'SHA256SUMS']
            changed = profile.json_bytes(incomplete)
            (root / release_signing.MANIFEST_NAME).write_bytes(changed)
            matching_pin = copy.deepcopy(pinned)
            matching_pin['legacy'][0]['manifest_sha256'] = hashlib.sha256(changed).hexdigest()
            rejects(lambda: verify(candidate=matching_pin))
        elif mode % 8 == 3:
            alias = Path(temporary) / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            rejects(lambda: verify(directory=alias))
            assert alias.is_symlink() and alias.resolve() == root
        elif mode % 8 == 4:
            (root / archive_name).write_bytes(archive + b'changed')
            rejects(verify)
        elif mode % 8 == 5:
            signature = profile.parse_json(files[release_signing.SIGNATURE_NAME])
            signature['algorithm'] = 'unsupported'
            (root / release_signing.SIGNATURE_NAME).write_bytes(profile.json_bytes(signature))
            rejects(verify)
        elif mode % 8 == 6:
            foreign = copy.deepcopy(pinned)
            foreign['legacy'][0]['public_key_sha256'] = '0' * 64
            rejects(lambda: verify(candidate=foreign))
        else:
            (root / release_signing.MANIFEST_NAME).write_bytes(seed + b' ')
            rejects(verify)
        for name, data in files.items():
            (root / name).write_bytes(data)

        (root / release_signing.BUNDLE_NAME).write_bytes(b'synthetic bundle, never trusted')
        environment = {'PATH': '/usr/bin:/bin', 'TMPDIR': temporary}
        for failed_position in (0, 1):
            calls = []

            def failed_verifier(arguments, **options):
                position = len(calls)
                assert position <= failed_position
                assert arguments[:3] == ['gh', 'attestation', 'verify']
                name = [release_signing.MANIFEST_NAME, release_signing.SIGNATURE_NAME][position]
                assert arguments[3] == str((root / name).resolve())
                expected = {'--bundle': str((root / release_signing.BUNDLE_NAME).resolve()),
                            '--hostname': 'github.com', '--repo': policy['repository'],
                            '--cert-identity': release_signing.identity(policy, 'release'),
                            '--cert-oidc-issuer': policy['issuer'], '--source-ref': policy['ref'],
                            '--source-digest': legacy['source_commit'],
                            '--signer-digest': legacy['source_commit'],
                            '--predicate-type': 'https://slsa.dev/provenance/v1'}
                assert arguments[-1] == '--deny-self-hosted-runners'
                options_only = arguments[4:-1]
                assert len(options_only) == 2 * len(expected)
                assert len(set(options_only[::2])) == len(expected)
                assert dict(zip(options_only[::2], options_only[1::2])) == expected
                assert options == {'check': True, 'timeout': 120, 'stdin': subprocess.DEVNULL,
                                   'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL,
                                   'env': environment}
                calls.append(name)
                if position == failed_position:
                    raise subprocess.CalledProcessError(1, arguments)
                # An earlier coordination acknowledgement only. Every whole
                # operation fails; this never supplies a cryptographic pass.
                return subprocess.CompletedProcess(arguments, 0)

            before = snapshot()
            with mock.patch.dict(release_signing.os.environ, environment, clear=True), \
                    mock.patch.object(release_signing.subprocess, 'run', side_effect=failed_verifier):
                try:
                    release_signing.verify_public(policy, root, policy['repository'], legacy['tag'],
                                                  legacy['source_commit'])
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise AssertionError('failed verifier acquired a pass')
            assert len(calls) == failed_position + 1 and snapshot() == before
        assert all((root / name).read_bytes() == data for name, data in files.items())
    assert policy == original_policy
    return accepted, seed
