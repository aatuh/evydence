#!/usr/bin/env python3
"""Discover immutable Action references and observe public Git objects without execution."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

import yaml

import dependency_policy as policy
from fixture_provenance import git_blob
from release_lifecycle import read_bytes
from release_scanner import capture
from support_matrix_artifacts import UniqueLoader

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOTS = ('.github/workflows', 'docs/github-actions')
MAX_WORKFLOW_BYTES = 512 * 1024
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_REQUESTS = 256
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_COMPONENTS = 128
MAX_REFERENCES = 1024
HEX = re.compile(r'[0-9a-f]{40}\Z')
PART = re.compile(r'[A-Za-z0-9_.-]{1,128}\Z')
LICENSE = re.compile(r'(?:licen[sc]e|copying|copyright|unlicense)(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)
NOTICE = re.compile(r'(?:notice|third[-_]?party[-_]?notices?)(?:[._-][A-Za-z0-9._-]+)?\Z', re.I)


class ActionSourceError(ValueError):
    def __init__(self):
        super().__init__('invalid or unavailable bounded Action source or workflow reference')


def require(value):
    if not value:
        raise ActionSourceError()


def repository(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value))
    return value.lower()


def path(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024)
    require(all(part not in {'.', '..'} and PART.fullmatch(part) for part in value.split('/')))
    return value


def external(value, *, pinned=True):
    require(isinstance(value, str) and 0 < len(value) <= 1200 and value.count('@') == 1)
    name, revision = value.split('@')
    path(name)
    parts = name.split('/')
    require(2 <= len(parts) <= 18)
    repo = repository('/'.join(parts[:2]))
    if pinned:
        require(HEX.fullmatch(revision))
    else:
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', revision)
                and all(part not in {'', '.', '..'} for part in revision.split('/')))
    return repo, '/'.join(parts[2:]), revision


def document(raw):
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_WORKFLOW_BYTES)
        result = yaml.load(raw.decode('utf-8'), Loader=UniqueLoader)
        require(isinstance(result, dict))
        return result
    except (ValueError, UnicodeError, yaml.YAMLError, RecursionError):
        raise ActionSourceError() from None


def steps(values):
    require(isinstance(values, list) and len(values) <= 512)
    result = []
    for index, step in enumerate(values):
        require(isinstance(step, dict) and ('uses' in step) != ('run' in step))
        if 'uses' in step:
            require(isinstance(step['uses'], str))
            result.append((step['uses'], index))
        else:
            require(isinstance(step['run'], str))
    return result


def workflow_paths(root):
    try:
        result = set()
        for folder in WORKFLOW_ROOTS:
            directory = Path(root) / folder
            require(not directory.is_symlink())
            if not directory.exists():
                continue
            require(directory.is_dir())
            for index, candidate in enumerate(directory.iterdir()):
                require(index < 256)
                if candidate.suffix not in {'.yml', '.yaml'}:
                    continue
                require(not candidate.is_symlink() and candidate.is_file())
                result.add(folder + '/' + path(candidate.name))
                require(len(result) <= 64)
        require(result)
        return result
    except (OSError, ValueError):
        raise ActionSourceError() from None


def references(values):
    rows = {}
    for index, (value, origin, location) in enumerate(values):
        require(index < MAX_REFERENCES)
        repo, folder, revision = external(value)
        name = repo + ('/' + folder if folder else '')
        require(origin in {'ci', 'workflow-example', 'action-dependency'} and isinstance(location, str) and len(location) <= 2048)
        require(all(32 <= ord(char) < 127 for char in location))
        identity = (name, revision)
        if identity not in rows:
            rows[identity] = {'ecosystem': 'github-actions', 'name': name, 'version': revision,
                              'origins': [], 'locations': [], 'license': None, 'license_status': 'unobserved',
                              'license_evidence': [], 'version_published_at': None,
                              'source': {'repository': repo, 'commit': revision, 'path': folder}}
        row = rows[identity]
        row['origins'] = sorted(set(row['origins'] + [origin]))
        row['locations'] = sorted(set(row['locations'] + [location]))
        require(len(rows) <= MAX_COMPONENTS)
    return [rows[key] for key in sorted(rows)]


def discover(root, inputs):
    try:
        names, refs, total = workflow_paths(root), [], 0
        for name in sorted(names):
            if name not in inputs:
                inputs[name] = read_bytes(root, name, MAX_WORKFLOW_BYTES)
            total += len(inputs[name]); require(total <= MAX_INPUT_BYTES)
            workflow = document(inputs[name])
            jobs = workflow.get('jobs')
            require(isinstance(jobs, dict) and 0 < len(jobs) <= 256)
            origin = 'ci' if name.startswith('.github/') else 'workflow-example'
            for job_name, job in jobs.items():
                require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,127}', job_name) and isinstance(job, dict))
                require(('uses' in job) != ('steps' in job))
                values = [(job['uses'], 'call')] if 'uses' in job else steps(job['steps'])
                for value, position in values:
                    require(isinstance(value, str))
                    if value.startswith('./'):
                        require(position == 'call' and path(value[2:]) in names
                                and value.startswith('./.github/workflows/'))
                        continue
                    refs.append((value, origin, name + '#jobs/' + job_name + '/steps/' + str(position)))
                    require(len(refs) <= MAX_REFERENCES)
        return references(refs)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise ActionSourceError() from None


def relative_file(base, value):
    require(isinstance(value, str) and 0 < len(value) <= 1024 and not value.startswith('/'))
    parts = base.split('/') if base else []
    for part in value.split('/'):
        require(part and (part in {'.', '..'} or PART.fullmatch(part)))
        if part == '..':
            require(parts); parts.pop()
        elif part != '.':
            parts.append(part)
    return path('/'.join(parts))


def nested(value):
    require(isinstance(value, str))
    if value.startswith('./'):
        relative_file('', value[2:])
        return {'kind': 'local-action', 'reference': value}
    if value.startswith('docker://'):
        require(re.fullmatch(r'docker://[A-Za-z0-9_./:@-]{1,1024}', value))
        return {'kind': 'container-action', 'reference': value}
    _repo, _folder, revision = external(value, pinned=False)
    return {'kind': 'github-action', 'reference': value, 'pinned': bool(HEX.fullmatch(revision))}


def runtime(raw, base):
    data = document(raw); runs = data.get('runs')
    require(isinstance(runs, dict))
    using = runs.get('using')
    require(isinstance(using, str) and using in {'node12', 'node16', 'node20', 'node24', 'composite', 'docker'})
    result = {'using': using, 'dependencies': []}
    if using.startswith('node'):
        require('main' in runs)
        result['entrypoints'] = {key: relative_file(base, runs[key]) for key in ('main', 'pre', 'post') if key in runs}
    elif using == 'docker':
        image = runs.get('image')
        require(isinstance(image, str) and re.fullmatch(r'[A-Za-z0-9_./:@-]{1,1024}', image))
        result['image'] = image if image.startswith('docker://') else relative_file(base, image)
    else:
        for value, _index in steps(runs.get('steps')):
            result['dependencies'].append(nested(value))
    return result


def api(repo, kind, sha=None):
    try:
        repo = repository(repo)
        require(kind in {'repository', 'commits', 'trees', 'blobs', 'resolve'})
        if kind == 'repository':
            require(sha is None); suffix = ''
        elif kind == 'resolve':
            external(repo + '@' + sha, pinned=False)
            suffix = '/commits/' + quote(sha, safe='')
        else:
            require(isinstance(sha, str) and HEX.fullmatch(sha))
            suffix = '/git/' + kind + '/' + sha
        endpoint = 'repos/' + repo + suffix
        environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'GH_TOKEN', 'GITHUB_TOKEN') if key in os.environ}
        environment.update(GH_PROMPT_DISABLED='1', GH_PAGER='cat', LC_ALL='C.UTF-8')
        raw = capture(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                       '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2026-03-10', endpoint],
                      ROOT, environment, 4 * 1024 * 1024, 30)
        result = policy.parse_document(raw)
        require(isinstance(result, dict))
        return result
    except (OSError, ValueError, TypeError, RecursionError):
        raise ActionSourceError() from None


class GitHubSources:
    def __init__(self, work, *, query=api):
        self.work, self.query = Path(work), query
        require(not self.work.is_symlink() and self.work.is_dir())
        self.count, self.total = 0, 0
        self.repos, self.commits, self.trees, self.blobs, self.results, self.stored = set(), {}, {}, {}, {}, set()
        self.resolved = {}

    def get(self, repo, kind, sha=None):
        self.count += 1; require(self.count <= MAX_REQUESTS)
        value = self.query(repo, kind, sha)
        self.total += len(json.dumps(value).encode()); require(self.total <= MAX_TOTAL_BYTES)
        require(isinstance(value, dict))
        return value

    def public(self, repo):
        if repo not in self.repos:
            metadata = self.get(repo, 'repository')
            require(metadata.get('private') is False and metadata.get('full_name', '').lower() == repo)
            self.repos.add(repo)

    def resolve(self, repo, revision):
        repo, _folder, revision = external(repo + '@' + revision, pinned=False)
        self.public(repo)
        if (repo, revision) not in self.resolved:
            value = self.get(repo, 'resolve', revision)
            sha = value.get('sha'); require(isinstance(sha, str) and HEX.fullmatch(sha))
            self.resolved[repo, revision] = sha
        return self.resolved[repo, revision]

    def root(self, repo, revision):
        self.public(repo)
        identity = repo, revision
        if identity not in self.commits:
            commit = self.get(repo, 'commits', revision)
            require(commit.get('sha') == revision and isinstance(commit.get('tree'), dict))
            sha = commit['tree'].get('sha'); require(isinstance(sha, str) and HEX.fullmatch(sha))
            self.commits[identity] = sha
        return self.commits[identity]

    def tree(self, repo, sha):
        if (repo, sha) not in self.trees:
            value = self.get(repo, 'trees', sha)
            require(value.get('sha') == sha and value.get('truncated') is False)
            entries = value.get('tree'); require(isinstance(entries, list) and len(entries) <= 4096)
            result = {}
            modes = {'100644': 'blob', '100755': 'blob', '120000': 'blob', '040000': 'tree', '160000': 'commit'}
            for entry in entries:
                require(isinstance(entry, dict))
                name = entry.get('path')
                require(isinstance(name, str) and 0 < len(name.encode()) <= 255 and name not in {'.', '..'}
                        and '/' not in name and '\\' not in name and all(ord(c) >= 32 and ord(c) != 127 for c in name))
                require(name not in result and entry.get('mode') in modes and entry.get('type') == modes[entry['mode']])
                require(isinstance(entry.get('sha'), str) and HEX.fullmatch(entry['sha']))
                result[name] = entry
            self.trees[repo, sha] = result
        return self.trees[repo, sha]

    def read(self, repo, entry, name, role):
        require(entry.get('mode') in {'100644', '100755'} and entry.get('type') == 'blob')
        size, sha = entry.get('size'), entry['sha']
        require(type(size) is int and 0 <= size <= MAX_FILE_BYTES)
        if (repo, sha) not in self.blobs:
            value = self.get(repo, 'blobs', sha)
            require(value.get('sha') == sha and value.get('encoding') == 'base64'
                    and type(value.get('size')) is int and value['size'] == size and isinstance(value.get('content'), str))
            raw = base64.b64decode(value['content'].replace('\n', ''), validate=True)
            require(len(raw) == size and git_blob(raw) == sha)
            digest = hashlib.sha256(raw).hexdigest()
            if digest not in self.stored:
                with (self.work / digest).open('xb') as target:
                    target.write(raw)
                self.stored.add(digest)
            self.blobs[repo, sha] = raw
        raw = self.blobs[repo, sha]; require(len(raw) == size)
        return raw, {'path': name, 'role': role, 'git_blob': sha, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': size}

    def fetch(self, row):
        try:
            repo, folder, revision = external(row['name'] + '@' + row['version'])
            require(row['ecosystem'] == 'github-actions' and row['source'] == {'repository': repo, 'commit': revision, 'path': folder})
            identity = row['name'], revision
            if identity in self.results:
                return copy.deepcopy(self.results[identity])
            root = self.root(repo, revision)
            tree, prefix, files, records = self.tree(repo, root), [], [], []
            parts = folder.split('/') if folder else []
            reusable = len(parts) == 3 and parts[:2] == ['.github', 'workflows'] and parts[-1].endswith(('.yml', '.yaml'))
            for directory in [None] + (parts[:-1] if reusable else parts):
                if directory is not None:
                    entry = tree.get(directory)
                    require(isinstance(entry, dict) and entry['mode'] == '040000')
                    tree = self.tree(repo, entry['sha']); prefix.append(directory)
                for name, entry in sorted(tree.items()):
                    if not (LICENSE.fullmatch(name) or NOTICE.fullmatch(name)):
                        continue
                    full = '/'.join(prefix + [name])
                    kind = 'notice' if NOTICE.fullmatch(name) or name.lower().startswith('copyright') else 'license'
                    raw, record = self.read(repo, entry, full, kind)
                    records.append(record)
                    files.append({'file': full, 'kind': kind, 'sha256': record['sha256'], 'content': raw})
                    require(len(files) <= 32)
            candidates = [parts[-1]] if reusable else [name for name in ('action.yml', 'action.yaml') if name in tree]
            require(len(candidates) == 1 and candidates[0] in tree)
            name = candidates[0]; full = '/'.join(prefix + [name])
            raw, record = self.read(repo, tree[name], full, 'manifest'); records.append(record)
            if reusable:
                observed_runtime = {'using': 'reusable-workflow', 'dependencies': []}
                jobs = document(raw).get('jobs'); require(isinstance(jobs, dict) and len(jobs) <= 256)
                for job in jobs.values():
                    require(isinstance(job, dict) and ('uses' in job) != ('steps' in job))
                    values = [(job['uses'], 0)] if 'uses' in job else steps(job['steps'])
                    observed_runtime['dependencies'].extend(nested(value) for value, _index in values)
                    require(len(observed_runtime['dependencies']) <= MAX_REFERENCES)
            else:
                observed_runtime = runtime(raw, '/'.join(prefix))
            result = {'verification': 'github-git-objects', 'root_tree': root, 'files': records, 'runtime': observed_runtime}, files
            self.results[identity] = result
            return copy.deepcopy(result)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            raise ActionSourceError() from None


def collect(rows, work):
    """Follow declared nested Actions, preserving mutable refs and observed resolutions."""
    try:
        client, pending, result, files = GitHubSources(work), copy.deepcopy(rows), {}, {}
        index = 0
        while index < len(pending):
            require(len(pending) <= 512)
            row = pending[index]; index += 1
            identity = row['name'], row['version']
            if identity in result:
                for field in ('origins', 'locations'):
                    result[identity][field] = sorted(set(result[identity][field] + row[field]))
                continue
            require(len(result) < MAX_COMPONENTS)
            observation, selected = client.fetch(row)
            for position, dependency in enumerate(observation['runtime']['dependencies']):
                if dependency['kind'] != 'github-action':
                    continue
                repo, folder, revision = external(dependency['reference'], pinned=False)
                resolved = revision if dependency['pinned'] else client.resolve(repo, revision)
                name = repo + ('/' + folder if folder else '')
                dependency['resolved_name'], dependency['resolved_commit'] = name, resolved
                pending.extend(references([(name + '@' + resolved, 'action-dependency',
                                            row['name'] + '@' + row['version'] + '#runtime/dependencies/' + str(position))]))
            row['source'].update(observation)
            result[identity], files[identity] = row, selected
        return [result[key] for key in sorted(result)], files
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ActionSourceError() from None
