#!/usr/bin/env python3
"""Check changelog delivery coverage against bounded, repository-local Git data."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile
import threading
import unicodedata

import change_fragments as changes
import release_lifecycle as lifecycle
import release_change_provider as provider

ROOT = Path(__file__).resolve().parents[1]
MAX_GIT_OUTPUT = 8 * 1024 * 1024
MAX_CHANGELOG = 2 * 1024 * 1024


class HistoryError(ValueError):
    """Safe source-history error without raw Git, fragment or provider output."""


def fragment_path(path):
    parts = path.split('/')
    return (len(parts) == 3 and parts[:2] == ['changes', 'fragments']
            and parts[2].endswith('.json'))


def visible_path(path):
    if fragment_path(path) or path in {'.EVYDENCE_CODEX_BACKLOG.md', 'HANDOFF.md', 'GOAL.txt'}:
        return False
    parts = path.split('/')
    if path.endswith('_test.go') or 'testdata' in parts:
        return False
    if path.startswith('scripts/test_') or path.startswith('tests/'):
        return False
    return True


class Repository:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.environment = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'LC_ALL': 'C.UTF-8', 'TZ': 'UTC',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
            'GIT_OPTIONAL_LOCKS': '0',
        }
        actual = self.data(['rev-parse', '--show-toplevel'], 4096).decode('utf-8').rstrip('\n')
        if Path(actual).resolve() != self.root:
            raise HistoryError('history root must be the repository root')

    def run(self, args, limit=MAX_GIT_OUTPUT, allowed=(0,)):
        argv = ['git', '--no-pager', '-c', 'core.fsmonitor=false',
                '-c', 'core.hooksPath=' + os.devnull, '-c', 'gc.auto=0', *args]
        try:
            child = subprocess.Popen(argv, cwd=self.root, env=self.environment,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            raise HistoryError('cannot start local Git reader') from None
        timer = threading.Timer(30, child.kill)
        timer.daemon = True
        timer.start()
        try:
            assert child.stdout is not None
            raw = child.stdout.read(limit + 1)
            if len(raw) > limit:
                child.kill()
                raise HistoryError('Git metadata exceeds its byte budget')
            code = child.wait()
            if code not in allowed:
                raise HistoryError('cannot read required Git metadata')
            return code, raw
        finally:
            timer.cancel()
            timer.join()
            if child.stdout is not None:
                child.stdout.close()
            if child.poll() is None:
                child.kill()
            child.wait()

    def data(self, args, limit=MAX_GIT_OUTPUT):
        return self.run(args, limit)[1]

    def commit(self, value):
        if not isinstance(value, str) or not changes.COMMIT.fullmatch(value):
            raise HistoryError('invalid source commit identity')
        return value

    def head(self):
        return self.commit(self.data(['rev-parse', '--verify', 'HEAD^{commit}'], 128).decode('ascii').strip())

    def parents(self, commit):
        raw = self.data(['rev-list', '--parents', '-n', '1', self.commit(commit)], 4096)
        try:
            values = raw.decode('ascii').split()
            if not values or values[0] != commit:
                raise HistoryError('invalid source parent metadata')
            return [self.commit(value) for value in values[1:]]
        except UnicodeError:
            raise HistoryError('invalid source parent identities') from None

    def common_ancestor(self, before, after):
        return self.commit(self.data(['merge-base', self.commit(before), self.commit(after)],
                                     128).decode('ascii').strip())

    def ancestor(self, before, after):
        return self.run(['merge-base', '--is-ancestor', self.commit(before), self.commit(after)],
                        128, allowed=(0, 1))[0] == 0

    def paths(self, args):
        raw = self.data(args)
        if raw and not raw.endswith(b'\0'):
            raise HistoryError('invalid Git path framing')
        try:
            values = [part.decode('utf-8') for part in raw.split(b'\0') if part]
        except UnicodeError:
            raise HistoryError('Git paths must use UTF-8') from None
        for path in values:
            if (Path(path).is_absolute() or '..' in Path(path).parts
                    or any(unicodedata.category(c).startswith('C') for c in path)):
                raise HistoryError('invalid repository path')
        return sorted(set(values))

    def difference(self, before, after):
        return self.paths(['diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                           '--name-only', '-z', self.commit(before), self.commit(after), '--'])

    def worktree(self, head):
        changed = self.paths(['diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                              '--name-only', '-z', self.commit(head), '--'])
        untracked = self.paths(['ls-files', '--others', '--exclude-standard', '-z'])
        return sorted(set(changed) | set(untracked))

    def blob(self, commit, path, limit=lifecycle.MAX_JSON_BYTES):
        if Path(path).is_absolute() or '..' in Path(path).parts:
            raise HistoryError('invalid Git blob path')
        raw = self.data(['ls-tree', '-z', self.commit(commit), '--', path], 4096)
        if not raw:
            return None
        try:
            header, name = raw.rstrip(b'\0').split(b'\t', 1)
            mode, kind, object_id = header.split()
            if name.decode('utf-8') != path or kind != b'blob' or mode not in (b'100644', b'100755'):
                raise HistoryError('Git input must be a regular file')
            object_id = self.commit(object_id.decode('ascii'))
            size_text = self.data(['cat-file', '-s', object_id], 64).decode('ascii').strip()
            if not re.fullmatch(r'[0-9]+', size_text) or int(size_text) > limit:
                raise HistoryError('Git blob exceeds its byte budget')
            data = self.data(['cat-file', 'blob', object_id], limit)
            if len(data) != int(size_text):
                raise HistoryError('Git blob size did not match its object')
            return data
        except (UnicodeError, ValueError):
            raise HistoryError('invalid Git file metadata') from None

    def deliveries(self, base, head):
        raw = self.data(['rev-list', '--first-parent', '--reverse', self.commit(base) + '..' + self.commit(head)])
        try:
            commits = [self.commit(value) for value in raw.decode('ascii').splitlines()]
            if len(commits) > 512:
                raise HistoryError('release delivery range exceeds its review budget')
            result = []
            for commit in commits:
                parents = self.data(['rev-list', '--parents', '-n', '1', commit], 4096).decode('ascii').split()
                if len(parents) < 2 or parents[0] != commit:
                    raise HistoryError('delivery must have a source parent')
                result.append((commit, self.commit(parents[1])))
            return result
        except UnicodeError:
            raise HistoryError('invalid Git source identities') from None


def json_blob(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=lifecycle.reject_duplicates,
                          parse_constant=lifecycle.reject_nonfinite)
    except (UnicodeError, ValueError, RecursionError):
        raise HistoryError('invalid change fragment JSON') from None


def read_fragment(repo, commit, path):
    identifier = Path(path).stem
    if not changes.IDENTIFIER.fullmatch(identifier):
        raise HistoryError('invalid fragment filename')
    raw = repo.blob(commit, path)
    return changes.validate_fragment(json_blob(raw), identifier) if raw is not None else None


def inspect(root, exemption=None, pull_request=None):
    try:
        repo = Repository(root)
        root = repo.root
        policy = changes.validate_policy(lifecycle.read_json(root, 'changes/policy.json'))
        metadata = lifecycle.read_json(root, 'release/current.json')
        release = lifecycle.current_release(metadata)
        lifecycle.installable_tag(lifecycle.validate_policy(
            lifecycle.read_json(root, 'release/lifecycle-policy.json')), metadata)
        head = repo.head()
        history_head, pull_delivery = head, None
        if pull_request is not None:
            provider.number(pull_request['number'])
            pull_base = repo.commit(pull_request['base_commit'])
            pull_head = repo.commit(pull_request['head_commit'])
            if type(pull_request['no_changelog']) is not bool:
                raise HistoryError('invalid pull request exemption state')
            if head != pull_head and repo.parents(head) != [pull_base, pull_head]:
                raise HistoryError('checkout must match exact PR head or its base/head merge')
            history_head = pull_base
            pull_delivery = (pull_head, repo.common_ancestor(pull_base, pull_head))
        adoption = policy['adoption_commit']
        previous = release['source_commit']
        if (not repo.ancestor(policy['legacy_release_commit'], adoption)
                or not repo.ancestor(adoption, head) or not repo.ancestor(previous, head)
                or not repo.ancestor(adoption, history_head) or not repo.ancestor(previous, history_head)):
            raise HistoryError('release/adoption source must be available ancestors of HEAD')
        if repo.ancestor(previous, adoption):
            if previous != policy['legacy_release_commit']:
                raise HistoryError('pre-adoption release must match the pinned legacy source')
            base = adoption
            include_legacy = any(visible_path(path) for path in repo.difference(previous, adoption))
        elif repo.ancestor(adoption, previous):
            base, include_legacy = previous, False
        else:
            raise HistoryError('release and adoption sources have incompatible ancestry')
        original = repo.blob(adoption, 'CHANGELOG.md', MAX_CHANGELOG)
        if original is None:
            raise HistoryError('missing adoption changelog')
        historical = changes.section(original.decode('utf-8'), 'Unreleased')[0]
        if hashlib.sha256(historical.encode('utf-8')).hexdigest() != policy['legacy_section_sha256']:
            raise HistoryError('legacy section digest does not bind the adoption source')
        changelog = lifecycle.read_bytes(root, 'CHANGELOG.md', MAX_CHANGELOG).decode('utf-8')
        changes.update_changelog(changelog, [], policy, include_legacy)
        all_changed = set(repo.difference(base, head))
        exempt_commits = []
        deliveries = repo.deliveries(base, history_head)
        if pull_delivery is not None:
            deliveries.append(pull_delivery)
        for commit, parent in deliveries:
            paths = repo.difference(parent, commit)
            if any(repo.blob(previous, path) is not None for path in paths if fragment_path(path)):
                raise HistoryError('published change fragments cannot be edited or removed in any delivery')
            notes = [read_fragment(repo, commit, path) for path in paths if fragment_path(path)]
            if any(visible_path(path) for path in paths) and not any(note is not None for note in notes):
                try:
                    if pull_delivery is not None and commit == pull_delivery[0]:
                        approved = pull_request['no_changelog']
                    else:
                        approved = exemption(commit) if exemption is not None else False
                except Exception:
                    raise HistoryError('cannot verify no-changelog delivery exemption') from None
                if approved is not True:
                    raise HistoryError('user-visible delivery needs a fragment or verified no-changelog PR label')
                exempt_commits.append(commit)
        pending = repo.worktree(head)
        all_changed.update(pending)
        fragments = []
        pending_notes = []
        for path in sorted(path for path in all_changed if fragment_path(path)):
            if repo.blob(previous, path) is not None:
                raise HistoryError('published change fragments cannot be edited or removed')
            if not os.path.lexists(root / path):
                continue
            identifier = Path(path).stem
            value = changes.validate_fragment(lifecycle.read_json(root, path), identifier)
            fragments.append(value)
            if path in pending:
                pending_notes.append(value)
        if any(visible_path(path) for path in pending) and not pending_notes:
            raise HistoryError('uncommitted user-visible changes need an updated fragment')
        return {'source_commit': head, 'previous_commit': previous, 'policy': policy,
                'fragments': fragments, 'include_legacy': include_legacy,
                'changed_paths': sorted(all_changed), 'exempt_commits': exempt_commits,
                'changelog': changelog}
    except (lifecycle.PolicyError, changes.ChangeError, provider.ProviderError,
            UnicodeError, OSError, KeyError, TypeError):
        raise HistoryError('invalid bounded change history input') from None


def replace_changelog(root, original, rendered):
    """Replace only the validated regular changelog, leaving it intact on failure."""
    root = Path(root).resolve()
    target = root / 'CHANGELOG.md'
    temporary = None
    try:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise HistoryError('changelog output must be a regular file')
        with tempfile.NamedTemporaryFile(prefix='.evydence-changelog-', dir=root,
                                         delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(rendered.encode('utf-8'))
            handle.flush()
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            os.fsync(handle.fileno())
        current = target.lstat()
        if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                or lifecycle.read_bytes(root, 'CHANGELOG.md', MAX_CHANGELOG) != original.encode('utf-8')):
            raise HistoryError('changelog changed during generation; retry without losing edits')
        os.replace(temporary, target)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--pull-request', type=int, default=os.environ.get('EVYDENCE_CHANGELOG_PULL_REQUEST') or None,
                        help='verify and check this open GitHub PR as a single delivery')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check', help='check source coverage and exact generated changelog')
    render = commands.add_parser('render', help='preview the generated changelog on stdout')
    render.add_argument('--write', action='store_true', help='atomically update CHANGELOG.md after validation')
    args = parser.parse_args(argv)
    try:
        github = provider.GitHub()
        pull = github.open_pull(args.pull_request) if args.pull_request is not None else None
        plan = inspect(args.root, exemption=github.merged_exemption, pull_request=pull)
        result = changes.update_changelog(plan['changelog'], plan['fragments'], plan['policy'],
                                          plan['include_legacy'], plan['exempt_commits'])
        if args.command == 'check':
            if result != plan['changelog']:
                raise HistoryError('changelog is stale; run scripts/release_history.py render --write')
            print('changelog source coverage and generated history: OK')
        elif args.write:
            replace_changelog(args.root, plan['changelog'], result)
        else:
            sys.stdout.write(result)
        return 0
    except (HistoryError, changes.ChangeError, lifecycle.PolicyError, provider.ProviderError, OSError):
        print('release history: invalid source coverage, fragment or generated changelog; '
              'check policy, delivery fragments and render --write', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
