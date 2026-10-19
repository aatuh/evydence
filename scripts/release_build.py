#!/usr/bin/env python3
"""Build unsigned release payloads; production validation and signing are separate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import release_artifacts as artifacts
import support_matrix


def build_environment(parent, current):
    environment = {key: parent[key] for key in [
        'PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'GOTMPDIR', 'GOCACHE', 'GOMODCACHE',
        'SSL_CERT_FILE', 'SSL_CERT_DIR',
    ] if parent.get(key)}
    environment.update(GOTOOLCHAIN='go' + current, GOENV='off', GOWORK='off', GOFLAGS='-p=1',
                       GOEXPERIMENT='', GOAMD64='v1', GOARM64='v8.0', GO386='sse2', CGO_ENABLED='0',
                       GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOGC='50',
                       GOPROXY='https://proxy.golang.org,direct', GOSUMDB='sum.golang.org',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    return environment


def capture(arguments, root, environment):
    return subprocess.run(arguments, cwd=root, env=environment, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30).stdout.strip()


def source_identity(root, expected, environment):
    commit = capture(['git', 'rev-parse', '--verify', 'HEAD'], root, environment)
    status = capture(['git', 'status', '--porcelain', '--untracked-files=all'], root, environment)
    if re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', commit) is None or commit != expected or status:
        raise ValueError('release source changed or is not clean')
    return commit


def prepare_directories(root, output, work):
    root, output, work = Path(root).resolve(), Path(output), Path(work)
    resolved = [output.resolve(), work.resolve()]
    if (any(root.is_relative_to(path) for path in resolved)
            or resolved[0].is_relative_to(resolved[1]) or resolved[1].is_relative_to(resolved[0])):
        raise ValueError('invalid release build directories')
    for path in [output, work]:
        if path.is_symlink() or path.exists() and (not path.is_dir() or any(path.iterdir())):
            raise ValueError('release build directories must be empty')
    for path in [output, work]:
        path.mkdir(parents=True, exist_ok=True)


def build_release(root, tag, output, work, expected_commit, *, parent_environment=None):
    artifacts.validate_coordinates(tag, expected_commit)
    root, output, work = Path(root).resolve(), Path(output), Path(work)
    policy = support_matrix.load_policy(root)
    environment = build_environment(os.environ if parent_environment is None else parent_environment,
                                    policy['go']['current'])
    commit = source_identity(root, expected_commit, environment)
    go_version = capture(['go', 'env', 'GOVERSION'], root, environment)
    if go_version != 'go' + policy['go']['current']:
        raise ValueError('release build requires the declared current compiler')
    epoch_text = capture(['git', 'show', '-s', '--format=%ct', commit], root, environment)
    if re.fullmatch(r'[0-9]{1,10}', epoch_text) is None:
        raise ValueError('invalid release source timestamp')
    epoch = int(epoch_text)
    manifest = artifacts.build_manifest(root, tag=tag, commit=commit, epoch=epoch, go_version=go_version)
    prepare_directories(root, output, work)
    output, work = output.resolve(), work.resolve()
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8')
    with (work / 'release-build-manifest.json').open('xb') as handle:
        handle.write(manifest_bytes)
    manifest_digest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
    identity_environment = dict(environment, EVYDENCE_BUILD_VERSION=tag, EVYDENCE_BUILD_COMMIT=commit,
                                EVYDENCE_BUILD_TIME=manifest['build_time'], EVYDENCE_BUILD_DIRTY='false',
                                EVYDENCE_BUILD_GO_VERSION=go_version,
                                EVYDENCE_BUILD_RELEASE_MANIFEST_DIGEST=manifest_digest)
    api_flags = capture(['sh', 'scripts/build_ldflags.sh'], root, identity_environment)
    for target in support_matrix.release_plan(policy):
        directory = work / ('evydence_' + tag + '_' + target['goos'] + '_' + target['goarch'])
        directory.mkdir()
        names = []
        for command in target['commands']:
            name = command + ('.exe' if target['goos'] == 'windows' else '')
            names.append(name)
            flags = '-s -w -buildid=' + (' ' + api_flags if command == 'evydence-api' else '')
            compiler_environment = dict(environment, GOOS=target['goos'], GOARCH=target['goarch'])
            subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-mod=readonly', '-pgo=off',
                            '-ldflags', flags, '-o', str(directory / name), './cmd/' + command],
                           cwd=root, env=compiler_environment, check=True)
        for name in sorted(artifacts.DOCUMENTS):
            shutil.copyfile(root / name, directory / name)
        suffix = '.zip' if target['goos'] == 'windows' else '.tar.gz'
        artifacts.write_archive(directory, output / (directory.name + suffix), epoch, names)
    source_identity(root, commit, environment)
    return manifest


def main(argv=None):
    parser = artifacts.Parser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args(argv)
    try:
        build_release(Path(__file__).resolve().parents[1], args.tag, args.output, args.work, args.expected_commit)
    except subprocess.CalledProcessError as error:
        print('release artifact build command failed', file=sys.stderr)
        return error.returncode if 1 <= error.returncode <= 125 else 1
    except (OSError, ValueError, subprocess.TimeoutExpired, support_matrix.PolicyError):
        print('release artifact build inputs or source are invalid', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
