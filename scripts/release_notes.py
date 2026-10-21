#!/usr/bin/env python3
"""Generate deterministic candidate notes and check them before local tagging."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys

import change_fragments as changes
import release_change_provider as provider
import release_history as history
import release_lifecycle as lifecycle

ROOT = Path(__file__).resolve().parents[1]
TOKENS = {'TAG', 'CHANGES', 'API', 'MIGRATIONS', 'SDK', 'SECURITY', 'SUPPORT', 'LIMITATIONS'}
HEADINGS = ('Changes', 'API Compatibility', 'Database Migrations', 'SDK Compatibility',
            'Security Notices', 'Support Window', 'Supported Profile',
            'Evidence In This Release Package', 'Install And Upgrade Notes', 'Known Limitations')
REQUIRED = ('Controlled self-hosted production candidate', 'not legal compliance proof',
            'not a certification', 'not a secure-release guarantee', 'complete SBOM proof',
            'authoritative vulnerability coverage', 'single API writer replica')
FORBIDDEN = re.compile(r'automatically compliant|certified secure|legally sufficient|SBOM is complete|'
                       r'all vulnerabilities detected|scanner findings are authoritative|regulator-ready without review', re.I)


class NotesError(ValueError):
    """Safe release error without input contents or provider diagnostics."""


def notes_path(tag):
    if not lifecycle.valid_tag(tag) or '-rc.' not in tag:
        raise NotesError('release notes require a canonical release candidate tag')
    return 'docs/reference/release-notes-' + tag + '.md'


def inventory(paths):
    return {
        'api': [path for path in paths if path == 'openapi.yaml'],
        'sdk': [path for path in paths if path.startswith('sdk/') and history.visible_path(path)],
        'migrations': [path for path in paths if path.startswith('migrations/') and path.endswith('.sql')],
    }


def changed_files(paths, absent):
    if len(paths) > 512:
        raise NotesError('release inventory exceeds its review budget')
    return '\n'.join('- `' + lifecycle.public_text(path) + '`' for path in paths) if paths else absent


def inputs(root, exemption=None, pull_request=None):
    """Validate source descriptions without selecting a candidate or install tag."""
    try:
        root = Path(root).resolve()
        policy = lifecycle.validate_policy(lifecycle.read_json(root, 'release/lifecycle-policy.json'))
        plan = history.inspect(root, exemption=exemption, pull_request=pull_request)
        repo = history.Repository(root)
        pending = repo.worktree(plan['source_commit'])
        paths = sorted(set(repo.difference(plan['previous_commit'], plan['source_commit'])) | set(pending))
        actual = inventory(paths)
        newer = inventory(plan['changed_paths'])
        fragments = plan['fragments']
        for field, required in [('api', 'changed'), ('sdk', 'changed'), ('migrations', 'required')]:
            declared = any(value['compatibility'][field] == required for value in fragments)
            # Pre-adoption changes are retained as historical inventory, rather
            # than attributed to a newly authored tooling fragment.
            if newer[field] and not declared:
                raise NotesError('changed contract files need matching compatibility declarations')
            if field == 'migrations' and declared and not newer[field]:
                raise NotesError('required migration declaration has no matching migration files')
        template = lifecycle.read_bytes(root, 'docs/reference/release-notes-template.md', 128 * 1024).decode('utf-8')
        if (set(re.findall(r'\{\{([^{}]*)\}\}', template)) != TOKENS
                or any(template.count('{{' + token + '}}') != 1 for token in TOKENS)
                or any(template.count('\n## ' + heading + '\n') != 1 for heading in HEADINGS)
                or any(value not in template for value in REQUIRED) or FORBIDDEN.search(template)
                or any(FORBIDDEN.search(str(value)) for value in fragments)
                or any(len(paths) > 512 for paths in actual.values())):
            raise NotesError('missing or contradictory release notes template')
        remainder = re.sub(r'\{\{([^{}]*)\}\}', '', template)
        if '{{' in remainder or '}}' in remainder:
            raise NotesError('invalid release notes template markers')
        return plan, actual, template, policy
    except (history.HistoryError, lifecycle.PolicyError, changes.ChangeError,
            OSError, UnicodeError, KeyError, TypeError):
        raise NotesError('cannot validate bounded release note inputs') from None


def generate(root, tag, exemption=None, pull_request=None):
    notes_path(tag)
    try:
        plan, actual, template, policy = inputs(root, exemption, pull_request)
        lifecycle.assert_not_withdrawn(policy, tag)
        fragments = plan['fragments']
        rendered = changes.render_unreleased(fragments, plan['policy'], plan['include_legacy'],
                                              plan['exempt_commits']).split('\n', 2)[2].strip()
        anchor = '#historical-source-snapshot-' + plan['policy']['adoption_commit'][:8] + '-not-a-release'
        rendered = rendered.replace('](' + anchor + ')', '](https://github.com/aatuh/evydence/blob/'
                                    + plan['policy']['adoption_commit'] + '/CHANGELOG.md#unreleased)')
        compatibility = '\n'.join('- `' + value['id'] + '`: ' + lifecycle.public_text(value['compatibility']['notes'])
                                   for value in sorted(fragments, key=lambda value: value['id']))
        api = changed_files(actual['api'], 'No OpenAPI contract file change in this source range.')
        api += '\n\nThis is a file inventory; semantic API compatibility is checked by the project OpenAPI gate.'
        sdk = changed_files(actual['sdk'], 'No SDK files changed in this source range.')
        migrations = changed_files(actual['migrations'], 'No database migration files changed in this source range.')
        migrations += ('\n\nReview the upgrade and rollback guidance before applying all committed migrations; '
                       'a changed-file inventory does not establish deployment compatibility.')
        if compatibility:
            api += '\n\nFragment compatibility notes:\n\n' + compatibility
            sdk += '\n\nFragment compatibility notes:\n\n' + compatibility
            migrations += '\n\nFragment compatibility notes:\n\n' + compatibility
        security = '\n'.join('- `' + value['id'] + '`: ' + lifecycle.public_text(value['security'])
                             for value in sorted(fragments, key=lambda value: value['id']))
        security += ('\n\nSecurity reports follow SECURITY.md. Earlier security changes remain in the historical '
                     'source snapshot when linked above. Local notes generation does not establish independent '
                     'review, vulnerability absence or external deployment assurance.')
        limits = '\n'.join('- `' + value['id'] + '`: ' + lifecycle.public_text(item)
                           for value in sorted(fragments, key=lambda value: value['id']) for item in value['limitations'])
        support = ('Support begins on publication and ends when the selected public release is superseded or withdrawn. '
                   'No fixed end date or response SLA is promised. Older releases receive best-effort support unless '
                   'a commercial agreement states otherwise. This candidate tag is not proof of publication; '
                   'release/lifecycle-policy.json and release/current.json own selection and withdrawal state.')
        values = {'TAG': tag, 'CHANGES': rendered, 'API': api, 'SDK': sdk, 'MIGRATIONS': migrations,
                  'SECURITY': security.strip(), 'SUPPORT': support, 'LIMITATIONS': limits}
        result = re.sub(r'\{\{([^{}]*)\}\}', lambda match: values[match[1]], template)
        if ('{{' in result or '}}' in result or FORBIDDEN.search(result)
                or any(value not in result for value in REQUIRED) or len(result.encode('utf-8')) > history.MAX_CHANGELOG):
            raise NotesError('invalid generated release notes')
        return result
    except (history.HistoryError, lifecycle.PolicyError, changes.ChangeError,
            OSError, UnicodeError, KeyError, TypeError):
        raise NotesError('cannot validate bounded release note inputs') from None


def validate_reviewed(root, tag, exemption=None):
    """Require exact committed notes; review authorization remains with the owner."""
    try:
        repo = history.Repository(root)
        head = repo.head()
        result = generate(root, tag, exemption=exemption)
        path = notes_path(tag)
        raw = lifecycle.read_bytes(repo.root, path, history.MAX_CHANGELOG)
        if repo.worktree(head) or raw != result.encode('utf-8') or repo.blob(head, path, history.MAX_CHANGELOG) != raw:
            raise NotesError('release requires a clean source and matching committed notes')
        plan = history.inspect(root, exemption=exemption)
        if (plan['source_commit'] != head or repo.head() != head or repo.worktree(head)
                or changes.update_changelog(plan['changelog'], plan['fragments'], plan['policy'],
                                             plan['include_legacy'], plan['exempt_commits']) != plan['changelog']):
            raise NotesError('release requires the exact generated source changelog')
        return result
    except (OSError, history.HistoryError, lifecycle.PolicyError, changes.ChangeError):
        raise NotesError('release notes must exist and match the committed source inputs') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--tag', help='required except for check-inputs')
    parser.add_argument('--pull-request', type=int, default=os.environ.get('EVYDENCE_CHANGELOG_PULL_REQUEST') or None,
                        help='exact open PR context for source previews only')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('render', help='print notes for review; no mutation')
    commands.add_parser('check-inputs', help='validate note inputs without requiring a release-specific file')
    commands.add_parser('check', help='require exact committed notes and a clean worktree')
    commands.add_parser('emit', help='print exact validated committed notes for packaging')
    commands.add_parser('check-artifact', help='compare packaged notes to exact validated committed notes')
    tag_command = commands.add_parser('tag', help='validate local tagging; defaults to a read-only plan')
    tag_command.add_argument('--create', action='store_true', help='explicitly create the local annotated tag')
    args = parser.parse_args(argv)
    try:
        client = provider.GitHub()
        if args.command in ('render', 'check-inputs'):
            pull = client.open_pull(args.pull_request) if args.pull_request is not None else None
            if args.command == 'check-inputs' and args.tag is None:
                inputs(args.root, exemption=client.merged_exemption, pull_request=pull)
                result = ''
            else:
                result = generate(args.root, args.tag, exemption=client.merged_exemption, pull_request=pull)
            print(result if args.command == 'render' else 'release note inputs: OK', end='' if args.command == 'render' else '\n')
        else:
            if args.pull_request is not None:
                raise NotesError('release preflight cannot use an open PR context')
            repo = history.Repository(args.root)
            head = repo.head()
            result = validate_reviewed(args.root, args.tag, exemption=client.merged_exemption)
            if repo.head() != head or repo.worktree(head):
                raise NotesError('release source changed during validation')
            if args.command == 'emit':
                sys.stdout.write(result)
            elif args.command == 'check-artifact':
                raw = lifecycle.read_bytes(Path(args.root).resolve(), 'dist/' + args.tag + '/release-notes.md',
                                           history.MAX_CHANGELOG)
                if raw != result.encode('utf-8'):
                    raise NotesError('packaged release notes differ from the committed source notes')
                print('packaged release notes: OK')
            elif args.command == 'tag':
                branch = repo.data(['symbolic-ref', '--quiet', 'HEAD'], 128).decode('ascii').strip()
                if branch != 'refs/heads/master':
                    raise NotesError('candidate tagging requires master')
                exists = repo.run(['show-ref', '--verify', '--quiet', 'refs/tags/' + args.tag], 128, allowed=(0, 1))[0]
                if exists == 0:
                    raise NotesError('candidate tag already exists; never overwrite release identity')
                if args.create:
                    message = 'Evydence ' + args.tag + '\nNotes SHA256: ' + hashlib.sha256(result.encode()).hexdigest()
                    # Explicit local mutation uses the operator's normal Git
                    # identity. Hooks and signing commands remain disabled;
                    # credentials and other inherited environment stay out.
                    environment = dict(repo.environment)
                    environment.pop('GIT_CONFIG_GLOBAL')
                    for key in ('HOME', 'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE',
                                'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE'):
                        if key in os.environ:
                            environment[key] = os.environ[key]
                    repo.run(['tag', '--no-sign', '--annotate', '--message', message, '--', args.tag, head],
                             4096, environment=environment)
                    print('local candidate tag created; no push or publication performed')
                else:
                    print('local tagging preflight: OK; --create is required to create a tag')
            else:
                print('committed release notes: OK')
        return 0
    except (NotesError, history.HistoryError, provider.ProviderError, lifecycle.PolicyError,
            OSError, UnicodeError):
        print('release notes: missing or contradictory source notes, compatibility, policy or tag inputs', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
