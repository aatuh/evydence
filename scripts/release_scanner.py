#!/usr/bin/env python3
"""Run the pinned scanner with bounded output and no ambient operator credentials."""
from __future__ import annotations

import os
from pathlib import Path
import selectors
import subprocess
import time

import release_evidence_profile as profile
import release_sbom
import support_matrix


SYFT_SOURCE_COMMIT = 'b254e6d92f28c3868a755f62fb3ca8f26e9fee76'
SCANNER_GO_VERSION = 'go' + support_matrix.load_policy()['go']['current']


def invalid():
    return ValueError('release scanner failed')


def environment(workspace, _parent=None):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(workspace), 'TMPDIR': str(workspace),
            'XDG_CONFIG_HOME': str(Path(workspace) / 'config'),
            'SYFT_CHECK_FOR_APP_UPDATE': 'false', 'SYFT_PARALLELISM': '1',
            'SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES': 'false',
            'SYFT_GOLANG_SEARCH_REMOTE_LICENSES': 'false',
            'GOMAXPROCS': '1', 'GOMEMLIMIT': '512MiB', 'GOGC': '50'}


def capture(arguments, workspace, child_environment, maximum, timeout):
    process = None
    try:
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(arguments, cwd=workspace, env=child_environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        output = bytearray()
        with process.stdout, selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise invalid()
                for key, _mask in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > maximum:
                        raise invalid()
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise invalid()
        return bytes(output)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise invalid() from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()


def verify_tool(executable, workspace):
    raw = capture([str(executable), 'version', '-o', 'json'], workspace,
                  environment(workspace), 8192, 10)
    record = profile.parse_json(raw)
    expected = {'application': 'syft', 'version': release_sbom.SYFT_VERSION,
                'gitCommit': SYFT_SOURCE_COMMIT, 'goVersion': SCANNER_GO_VERSION,
                'platform': 'linux/amd64'}
    if any(record.get(key) != value for key, value in expected.items()):
        raise invalid()


def configuration(workspace):
    workspace = Path(workspace)
    workspace.mkdir(mode=0o700)
    configuration_file = workspace / 'scanner.json'
    configuration_file.write_bytes(profile.json_bytes({
        'check-for-app-update': False, 'parallelism': 1,
        'golang': {'search-local-mod-cache-licenses': False, 'search-local-vendor-licenses': False,
                   'search-remote-licenses': False},
    }))
    return configuration_file


def scan(executable, subject, workspace):
    configuration_file = configuration(workspace)
    raw = capture([str(executable), 'scan', 'file:' + str(subject['path'].resolve()),
                   '--config', str(configuration_file.resolve()), '--parallelism', '1',
                   '--override-default-catalogers', 'go-module-binary-cataloger',
                   '-o', 'cyclonedx-json@1.6', '--quiet'], workspace,
                  environment(workspace), profile.MAX_JSON_BYTES, 180)
    components = release_sbom.public_components(profile.parse_json(raw))
    return release_sbom.bound_bom(subject, components)


def scan_container(executable, archive, subject, workspace):
    configuration_file = configuration(workspace)
    raw = capture([str(executable), 'scan', 'oci-archive:' + str(Path(archive).resolve()),
                   '--config', str(configuration_file.resolve()), '--parallelism', '1',
                   '--override-default-catalogers', 'apk-db-cataloger',
                   '--override-default-catalogers', 'go-module-binary-cataloger',
                   '-o', 'cyclonedx-json@1.6', '--quiet'], workspace,
                  environment(workspace), profile.MAX_JSON_BYTES, 180)
    components = release_sbom.public_components(profile.parse_json(raw), allow_apk=True)
    if not all(any(component.get('purl', '').startswith('pkg:' + ecosystem + '/') for component in components)
               for ecosystem in ('golang', 'apk')):
        raise invalid()
    return release_sbom.bound_bom(subject, components)
