#!/usr/bin/env python3
"""Discover declared image sources and project digest-bound scanner observations."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
import uuid
from urllib.parse import parse_qsl, unquote, urlsplit

import yaml

import dependency_actions as actions
import dependency_image_registry as registry
import dependency_inventory as inventory
import dependency_policy as policy
from release_lifecycle import read_bytes
import release_scanner
import release_evidence_tools as tools
from support_matrix_artifacts import UniqueLoader

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'evydence-dependency-images.v1'
REPORT = 'docs/reference/dependency-image-inventory.json'
GENERATOR_FILES = ('scripts/dependency_images.py', 'scripts/dependency_image_registry.py',
                   'scripts/release_scanner.py', 'scripts/release_evidence_tools.py',
                   'scripts/release_sbom.py', 'scripts/release_evidence_profile.py',
                   'scripts/support_matrix.py', 'release/support-matrix.json') + tools.LOCKS
MAX_PACKAGES = 8192
INPUTS = ('Dockerfile', 'deploy/local-dependencies/Dockerfile', 'docker-compose.yml',
          'compose.production-like.yml', 'deploy/airgap/manifest.yaml',
          'deploy/helm/evydence/values.yaml', 'docs/reference/dependency-inventory.json')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/+~-]{0,1023}\Z')
VERSION = re.compile(r'[A-Za-z0-9(][A-Za-z0-9._+~:()-]{0,255}\Z')


class ImageInventoryError(ValueError):
    def __init__(self):
        super().__init__('invalid or unavailable bounded image inventory observation')


def require(value):
    if not value:
        raise ImageInventoryError()


def docker_bases(raw):
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= 512 * 1024)
        result, aliases = [], set()
        for line in raw.decode('utf-8').splitlines():
            if not re.match(r'(?i:^\s*FROM\s)', line): continue
            match = re.fullmatch(r'(?i:FROM)\s+(\S+)(?:\s+(?i:AS)\s+([A-Za-z0-9_.-]+))?\s*', line.strip())
            require(match is not None)
            value, alias = match.groups()
            if value not in aliases:
                registry.reference(value); result.append(value)
            if alias: aliases.add(alias)
        require(result)
        return result
    except (ValueError, UnicodeError, TypeError):
        raise ImageInventoryError() from None


def discover(root):
    try:
        names = set(INPUTS) | actions.workflow_paths(root)
        inputs = {name: read_bytes(root, name, inventory.MAX_BYTES) for name in sorted(names)}
        snapshot = policy.parse_document(inputs['docs/reference/dependency-inventory.json'])
        require(snapshot.get('schema') == inventory.SCHEMA and isinstance(snapshot.get('components'), list))
        require(set(snapshot['generator']['files']) == set(inventory.GENERATOR_FILES))
        for name in inventory.GENERATOR_FILES:
            raw = read_bytes(root, name, inventory.MAX_BYTES)
            require(hashlib.sha256(raw).hexdigest() == snapshot['generator']['files'][name])
            inputs[name] = raw
        for name in actions.workflow_paths(root):
            require(hashlib.sha256(inputs[name]).hexdigest() == snapshot['inputs'][name])
        rows = {}
        def add(value, location, build=None, *, operator=False):
            require(isinstance(value, str) and len(value) <= 512)
            if operator or value == '${EVYDENCE_IMAGE:-evydence:local}':
                kind = 'operator-selected'
            elif value.startswith('evydence-local-'):
                match = re.fullmatch(r'evydence-local-(minio|mc):[0-9]{8}-[0-9a-f]{12}', value)
                require(match and isinstance(build, dict) and build.get('context') == './deploy/local-dependencies'
                        and build.get('target') == match[1])
                kind = 'source-build'
            else:
                parsed = registry.reference(value)
                value = parsed['name'] + (':' + parsed['tag'] if parsed['tag'] else '') + ('@' + parsed['digest'] if parsed['digest'] else '')
                kind = 'registry'
            identity = kind, value
            if identity not in rows: rows[identity] = {'reference': value, 'kind': kind, 'locations': []}
            rows[identity]['locations'] = sorted(set(rows[identity]['locations'] + [location]))
            require(len(rows) <= 64)
        for name in ('Dockerfile', 'deploy/local-dependencies/Dockerfile'):
            for index, value in enumerate(docker_bases(inputs[name])): add(value, name + '#base/' + str(index))
        def yaml_document(name):
            result = yaml.load(inputs[name].decode('utf-8'), Loader=UniqueLoader)
            require(isinstance(result, dict)); return result
        for name in ('docker-compose.yml', 'compose.production-like.yml'):
            services = yaml_document(name).get('services'); require(isinstance(services, dict) and len(services) <= 128)
            for identity, service in services.items():
                require(isinstance(service, dict))
                add(service['image'], name + '#services/' + identity, service.get('build'))
        for name in sorted(actions.workflow_paths(root)):
            for identity, job in yaml_document(name)['jobs'].items():
                for service_name, service in job.get('services', {}).items():
                    add(service['image'], name + '#jobs/' + identity + '/services/' + service_name)
                if 'container' in job:
                    container = job['container']
                    add(container['image'] if isinstance(container, dict) else container, name + '#jobs/' + identity + '/container')
        airgap = yaml_document('deploy/airgap/manifest.yaml')
        require(isinstance(airgap.get('images'), list) and len(airgap['images']) <= 64)
        for image in airgap['images']:
            add(image['repository'] + ':' + image['tag'] + '@' + image['digest'], 'deploy/airgap/manifest.yaml#images/' + image['name'])
        helm = yaml_document('deploy/helm/evydence/values.yaml')['image']
        require(helm['repository'] == 'ghcr.io/aatuh/evydence' and isinstance(helm['tag'], str))
        if helm['tag']:
            add(helm['repository'] + ':' + helm['tag'], 'deploy/helm/evydence/values.yaml#image')
        else:
            add(helm['repository'] + ':operator-selected', 'deploy/helm/evydence/values.yaml#image', operator=True)
        for component in snapshot['components']:
            if component['ecosystem'] != 'github-actions': continue
            runtime = component['source']['runtime']
            if runtime.get('using') == 'docker':
                require(runtime.get('image', '').startswith('docker://'))
                add(runtime['image'], component['name'] + '@' + component['version'] + '#runtime/image')
            for dependency in runtime['dependencies']:
                if dependency['kind'] == 'container-action': add(dependency['reference'], component['name'] + '#runtime/dependency')
        return [rows[key] for key in sorted(rows)], inputs
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError, yaml.YAMLError):
        raise ImageInventoryError() from None


def package(row):
    require(isinstance(row, dict) and row.get('type') in {'apk', 'deb', 'go-module'})
    name, version, purl = row.get('name'), row.get('version'), row.get('purl')
    require(isinstance(name, str) and (NAME.fullmatch(name) or row['type'] == 'apk'
            and re.fullmatch(r'\.[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}', name))
            and all(part not in {'.', '..'} for part in name.split('/'))
            and isinstance(version, str) and VERSION.fullmatch(version))
    require(isinstance(purl, str) and 0 < len(purl) <= 2048 and all(32 < ord(char) < 127 for char in purl))
    parsed = urlsplit(purl)
    ecosystem = {'apk': 'apk', 'deb': 'deb', 'go-module': 'golang'}[row['type']]
    require(parsed.scheme == 'pkg' and not parsed.netloc and not parsed.fragment and parsed.path.startswith(ecosystem + '/'))
    decoded = unquote(parsed.path[len(ecosystem) + 1:], errors='strict')
    require(all(part not in {'.', '..'} for part in decoded.split('/')))
    if '@' in decoded:
        coordinate, package_version = decoded.rsplit('@', 1)
        require(package_version == version or row['type'] == 'go-module' and name == 'stdlib' and package_version == version.removeprefix('go'))
    else:
        coordinate = decoded; require(version in {'UNKNOWN', '(devel)'})
    require(coordinate == name if row['type'] == 'go-module' else coordinate.rsplit('/', 1)[-1] == name)
    pairs = parse_qsl(parsed.query, strict_parsing=True, errors='strict', max_num_fields=8)
    require(len(pairs) == len(dict(pairs)) and all(re.fullmatch(r'[a-z][a-z0-9_]{0,63}', key)
                and re.fullmatch(r'[A-Za-z0-9._+~:-]{1,128}', value) for key, value in pairs))
    licenses = row.get('licenses'); require(isinstance(licenses, list) and len(licenses) <= 64)
    expressions, unsupported = set(), False
    for license in licenses:
        require(isinstance(license, dict))
        value = license.get('spdxExpression', license.get('value'))
        if not isinstance(value, str) or not value.strip() or value.strip().upper() in policy.UNKNOWN_LICENSES:
            unsupported = True; continue
        try:
            policy.license_allowed(value, {'allowed_licenses': ['MIT'], 'allowed_with': []})
            expressions.add(value)
        except policy.PolicyError: unsupported = True
    expression = next(iter(expressions)) if len(expressions) == 1 and not unsupported else None
    status = 'scanner-declared' if expression else 'multiple-declarations' if len(expressions) > 1 else 'unsupported' if unsupported else 'not-found'
    return {'name': name, 'version': version, 'type': row['type'], 'purl': purl,
            'license': expression, 'license_status': status, 'license_declarations': sorted(expressions)}


def project(raw, expected_manifest, expected_config):
    try:
        data = policy.parse_document(raw)
        source = data.get('source'); require(isinstance(source, dict) and source.get('type') == 'image')
        metadata = source.get('metadata'); require(isinstance(metadata, dict))
        manifest_raw = base64.b64decode(metadata['manifest'], validate=True)
        config_raw = base64.b64decode(metadata['config'], validate=True)
        manifest_digest = 'sha256:' + hashlib.sha256(manifest_raw).hexdigest()
        config_digest = 'sha256:' + hashlib.sha256(config_raw).hexdigest()
        require(expected_manifest is None or manifest_digest == expected_manifest)
        require(config_digest == expected_config and metadata.get('imageID') == config_digest
                and metadata.get('manifestDigest') == manifest_digest)
        manifest, config = policy.parse_document(manifest_raw), policy.parse_document(config_raw)
        require(type(manifest.get('schemaVersion')) is int and manifest['schemaVersion'] == 2 and manifest.get('mediaType') in registry.MANIFESTS)
        descriptor = registry.descriptor(manifest['config'], {registry.OCI_CONFIG, registry.DOCKER_CONFIG}, registry.MAX_JSON_BYTES)
        require(descriptor['digest'] == config_digest and descriptor['size'] == len(config_raw))
        require(metadata.get('os') == config.get('os') == 'linux'
                and metadata.get('architecture') == config.get('architecture') == 'amd64')
        layers = manifest.get('layers'); rootfs = config.get('rootfs')
        require(isinstance(layers, list) and 0 < len(layers) <= registry.MAX_LAYERS
                and isinstance(rootfs, dict) and rootfs.get('type') == 'layers'
                and isinstance(rootfs.get('diff_ids'), list) and len(rootfs['diff_ids']) == len(layers)
                and all(isinstance(value, str) and registry.DIGEST.fullmatch(value) for value in rootfs['diff_ids']))
        for layer in layers: registry.descriptor(layer, registry.LAYERS, registry.MAX_IMAGE_BYTES)
        artifacts = data.get('artifacts'); require(isinstance(artifacts, list) and 0 < len(artifacts) <= MAX_PACKAGES)
        result = {}
        for artifact in artifacts:
            value = package(artifact); identity = value['purl']
            require(identity not in result or value == result[identity]); result[identity] = value
        return {'verification': 'manifest-config-and-scanner-observations', 'image_id': config_digest,
                'manifest_digest': manifest_digest, 'platform': 'linux/amd64', 'scanner_output_sha256': hashlib.sha256(raw).hexdigest(),
                'packages': [result[key] for key in sorted(result)]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise ImageInventoryError() from None


def scan(executable, row, resolution, work):
    try:
        work = Path(work)
        if row['kind'] == 'registry':
            parsed = registry.reference(row['reference'])
            require(registry.DIGEST.fullmatch(resolution['manifest_digest']))
            target = 'registry:' + parsed['name'] + '@' + resolution['manifest_digest']
            expected_manifest, expected_config = resolution['manifest_digest'], resolution['config']['digest']
        else:
            require(row['kind'] == 'source-build' and registry.DIGEST.fullmatch(row['image_id']))
            target = 'docker:' + row['image_id']; expected_manifest, expected_config = None, row['image_id']
        configuration = release_scanner.configuration(work / 'config')
        raw = inventory._run([str(executable), 'scan', target, '--platform', 'linux/amd64',
                              '--config', str(configuration), '--parallelism', '1',
                              '--override-default-catalogers', 'apk-db-cataloger',
                              '--override-default-catalogers', 'dpkg-db-cataloger',
                              '--override-default-catalogers', 'go-module-binary-cataloger',
                              '-o', 'syft-json', '--quiet'], work, release_scanner.environment(work),
                             timeout=600, log=work / 'scan.log')
        result = project(raw, expected_manifest, expected_config)
        with (work / 'scanner.json').open('xb') as stream: stream.write(raw)
        return result
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ImageInventoryError() from None


def generator_inputs(root):
    return {name: read_bytes(root, name, inventory.MAX_BYTES) for name in GENERATOR_FILES}


def collect(root, work_root, executable, local_images):
    """Scan exact resolved manifests/local IDs; retain private work on failure."""
    try:
        rows, inputs = discover(root)
        inputs.update(generator_inputs(root))
        require(isinstance(local_images, dict) and set(local_images) == {
            row['reference'] for row in rows if row['kind'] == 'source-build'})
        require(all(isinstance(value, str) and registry.DIGEST.fullmatch(value) for value in local_images.values()))
        executable = Path(executable).absolute()
        recipe = tools.recipe_digest()
        require(tools.verify_installation(executable.parent, recipe) == executable)
        binary_sha = tools.file_digest(executable)
        work_root = Path(work_root)
        require(not work_root.is_symlink() and work_root.is_dir())
        work = Path(tempfile.mkdtemp(prefix='dependency-images-', dir=work_root))
        release_scanner.verify_tool(executable, work)
        images = []
        for index, declaration in enumerate(rows):
            row = dict(declaration)
            if row['kind'] == 'operator-selected':
                row['status'] = 'operator-selected'
            else:
                target = work / str(index); target.mkdir(mode=0o700)
                resolution = None
                if row['kind'] == 'registry':
                    resolution = registry.resolve(registry.reference(row['reference']))
                    row['resolution'] = resolution
                else:
                    row['image_id'] = local_images[row['reference']]
                row['observation'] = scan(executable, row, resolution, target)
                row['status'] = 'scanned'
                print('dependency-images: scanned ' + row['reference'] + ' (' +
                      str(len(row['observation']['packages'])) + ' package observations)', flush=True)
            images.append(row)
        # Discovery and scanner identity must remain stable for the entire run.
        fresh_rows, fresh_inputs = discover(root); fresh_inputs.update(generator_inputs(root))
        require(rows == fresh_rows and inputs == fresh_inputs and all(
            read_bytes(root, name, inventory.MAX_BYTES) == raw for name, raw in inputs.items()))
        require(tools.file_digest(executable) == binary_sha)
        return {'schema': SCHEMA, 'observed_at': datetime.now(timezone.utc).isoformat(),
                'scope': 'declared-linux-amd64-images', 'complete_artifact_sbom': False,
                'catalogers': ['apk-db-cataloger', 'dpkg-db-cataloger', 'go-module-binary-cataloger'],
                'inputs': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(inputs.items())},
                'scanner': {'name': 'syft', 'version': tools.release_sbom.SYFT_VERSION,
                            'recipe_sha256': recipe, 'binary_sha256': binary_sha},
                'coverage': {'declared': len(images), 'scanned': sum(row['status'] == 'scanned' for row in images),
                             'operator_selected': sum(row['status'] == 'operator-selected' for row in images)},
                'images': images}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ImageInventoryError() from None


def output_directory(root, relative, replace):
    path, directory = Path(relative), None
    try:
        require(not path.is_absolute() and path.parts and '..' not in path.parts)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        try:
            old = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None:
            require(replace and stat.S_ISREG(old.st_mode))
            previous = policy.parse_document(read_bytes(root, relative, inventory.MAX_BYTES))
            require(isinstance(previous, dict) and previous.get('schema') == SCHEMA)
        return directory, old
    except (OSError, ValueError):
        if directory is not None: os.close(directory)
        raise ImageInventoryError() from None


def write_report(root, relative, report, *, replace=False):
    require(isinstance(report, dict) and report.get('schema') == SCHEMA)
    raw = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()
    require(len(raw) <= inventory.MAX_BYTES)
    directory, old = output_directory(root, relative, replace)
    temporary = None; name = Path(relative).name
    try:
        candidate = '.dependency-images-' + uuid.uuid4().hex
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=directory)
        temporary = candidate
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if old is None:
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        else:
            require(os.stat(name, dir_fd=directory, follow_symlinks=False) == old)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    except (OSError, ValueError):
        raise ImageInventoryError() from None
    finally:
        if temporary is not None: os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def check(root, report):
    """Offline source binding, coverage and coordinate checks; no provider query."""
    try:
        require(isinstance(report, dict) and report.get('schema') == SCHEMA
                and report.get('scope') == 'declared-linux-amd64-images'
                and report.get('complete_artifact_sbom') is False)
        scanner = report['scanner']
        require(set(scanner) == {'name', 'version', 'recipe_sha256', 'binary_sha256'}
                and scanner['name'] == 'syft' and scanner['version'] == tools.release_sbom.SYFT_VERSION
                and scanner['recipe_sha256'] == tools.recipe_digest()
                and isinstance(scanner['binary_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', scanner['binary_sha256']))
        rows, inputs = discover(root); inputs.update(generator_inputs(root))
        require(report['inputs'] == {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(inputs.items())})
        images = report['images']; require(isinstance(images, list) and len(images) == len(rows))
        scanned = 0
        for declaration, row in zip(rows, images):
            require(all(row[key] == value for key, value in declaration.items()))
            if declaration['kind'] == 'operator-selected':
                require(row['status'] == 'operator-selected' and 'observation' not in row); continue
            scanned += 1
            require(row['status'] == 'scanned')
            observation = row['observation']
            require(observation['verification'] == 'manifest-config-and-scanner-observations'
                    and observation['platform'] == 'linux/amd64'
                    and registry.DIGEST.fullmatch(observation['manifest_digest'])
                    and registry.DIGEST.fullmatch(observation['image_id'])
                    and re.fullmatch(r'[0-9a-f]{64}', observation['scanner_output_sha256']))
            if row['kind'] == 'registry':
                resolution = row['resolution']
                require(resolution['manifest_digest'] == observation['manifest_digest']
                        and resolution['config']['digest'] == observation['image_id'])
                requested = registry.reference(row['reference'])
                require(requested['digest'] is None or requested['digest'] == resolution['root_digest'])
            else: require(row['image_id'] == observation['image_id'])
            packages = observation['packages']; require(isinstance(packages, list) and 0 < len(packages) <= MAX_PACKAGES)
            identities = set()
            for value in packages:
                require(set(value) == {'name', 'version', 'purl', 'type', 'license', 'license_status', 'license_declarations'}
                        and isinstance(value['license_declarations'], list) and len(value['license_declarations']) <= 64)
                source = {key: value[key] for key in ('name', 'version', 'purl', 'type')}
                source['licenses'] = [{'spdxExpression': expression} for expression in value['license_declarations']]
                verified = package(source)
                require(value['license_declarations'] == verified['license_declarations'])
                require(all(value[key] == verified[key] for key in source if key != 'licenses'))
                require(value['license_status'] in {'scanner-declared', 'multiple-declarations', 'unsupported', 'not-found'})
                require(value['license'] == (verified['license'] if value['license_status'] == 'scanner-declared' else None))
                require(value['license_status'] != 'scanner-declared' or verified['license_status'] == 'scanner-declared')
                require(value['license_status'] != 'multiple-declarations' or len(value['license_declarations']) > 1)
                require(value['license_status'] != 'not-found' or not value['license_declarations'])
                require(value['license_status'] != 'unsupported' or len(value['license_declarations']) <= 1)
                require(value['purl'] not in identities); identities.add(value['purl'])
        require(report['coverage'] == {'declared': len(rows), 'scanned': scanned, 'operator_selected': len(rows) - scanned})
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ImageInventoryError() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', default=REPORT)
    parser.add_argument('--check', action='store_true', help='Check the saved observation against current inputs offline.')
    parser.add_argument('--replace', action='store_true')
    parser.add_argument('--work-root', type=Path)
    parser.add_argument('--syft', type=Path)
    parser.add_argument('--local-images', type=Path, help='JSON mapping of declared fixture tags to exact existing local image IDs.')
    args = parser.parse_args(argv)
    old_handlers = {}
    try:
        def interrupted(_signum, _frame):
            raise ImageInventoryError()
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, interrupted)
        if args.check:
            check(args.root, policy.parse_document(read_bytes(args.root, args.output, inventory.MAX_BYTES)))
            print('dependency-images: offline source binding and coverage passed')
        else:
            require(args.work_root is not None and args.syft is not None and args.local_images is not None)
            directory, _old = output_directory(args.root, args.output, args.replace); os.close(directory)
            with inventory.regular_stream(args.local_images.parent, args.local_images.name) as stream:
                local = policy.parse_document(stream.read(65537))
            report = collect(args.root, args.work_root, args.syft, local)
            check(args.root, report)
            write_report(args.root, args.output, report, replace=args.replace)
            print('dependency-images: wrote source-bound image observations')
        return 0
    except (OSError, ValueError, TypeError):
        print('dependency-images: operation failed; inspect retained private scanner logs', file=sys.stderr)
        return 2
    finally:
        for signum, handler in old_handlers.items(): signal.signal(signum, handler)


if __name__ == '__main__':
    sys.exit(main())
