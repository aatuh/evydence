#!/usr/bin/env python3
"""Generate source-bound maintenance review signals; age is not abandonment or safety."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys

import dependency_images as images
import dependency_inventory as inventory
import dependency_maintenance_sources as sources
import dependency_policy as policy
import dependency_reports as reports
from release_lifecycle import read_bytes

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'evydence-dependency-maintenance.v1'
REPORT = 'docs/reference/dependency-maintenance.json'
FILES = ('scripts/dependency_maintenance.py', 'scripts/dependency_maintenance_sources.py', 'scripts/dependency_reports.py')
LIMITS = {'selected_version_age_days': 365, 'repository_no_push_days': 730}


class MaintenanceError(ValueError):
    def __init__(self): super().__init__('invalid or unavailable source-bound dependency maintenance report')


def require(value):
    if not value: raise MaintenanceError()


def identity(row):
    require(isinstance(row, dict) and row.get('ecosystem') in policy.ECOSYSTEMS)
    values = tuple(row.get(key) for key in ('ecosystem', 'name', 'version'))
    require(all(isinstance(value, str) and 0 < len(value) <= 1024
                and all(32 < ord(char) < 127 for char in value) for value in values))
    return values


def inputs(root):
    try:
        declarations, frozen = images.discover(root)
        frozen.update(images.generator_inputs(root))
        raw = read_bytes(root, images.REPORT, inventory.MAX_BYTES)
        image_report = policy.parse_document(raw); images.check(root, image_report)
        frozen[images.REPORT] = raw
        primary = policy.parse_document(frozen['docs/reference/dependency-inventory.json'])
        names = set(inventory.GENERATOR_FILES) | {inventory.fixture_sources.CATALOG, 'release/support-matrix.json',
            'tools/requirements-qa.txt', 'site/marketing/package.json', 'site/marketing/package-lock.json'}
        for _scope, mod, sums, _main in inventory.GRAPHS: names.update((mod, sums))
        names.update(inventory.go_tools.INPUTS)
        primary_inputs = {name: read_bytes(root, name, inventory.MAX_BYTES) for name in sorted(names)}
        inventory.fixture_components(root, primary_inputs)
        inventory.action_sources.discover(root, primary_inputs)
        require(primary['inputs'] == {name: hashlib.sha256(raw).hexdigest() for name, raw in primary_inputs.items()
                                      if name not in inventory.GENERATOR_FILES})
        frozen.update(primary_inputs)
        frozen.update({name: read_bytes(root, name, inventory.MAX_BYTES) for name in FILES})
        components = primary['components']; require(isinstance(components, list) and 0 < len(components) <= 8192)
        identities = [identity(row) for row in components]; require(len(identities) == len(set(identities)))
        require(len(image_report['images']) == len(declarations))
        return components, image_report['images'], frozen
    except (OSError, ValueError, KeyError, TypeError, AttributeError): raise MaintenanceError() from None


def age(value, now):
    value = sources.timestamp(value)
    if value is None: return None, None, False
    selected = datetime.fromisoformat(value.replace('Z', '+00:00'))
    delta = now - selected
    return value, max(0, delta.days) if delta.total_seconds() >= -86400 else None, delta.total_seconds() < -86400


def review(component, metadata, repository, now):
    try:
        ecosystem, name, version = identity(component)
        require(isinstance(now, datetime) and now.tzinfo is not None)
        requested = metadata['repository']; gaps, signals = set(), set()
        if metadata.get('metadata_status') in {'not-found', 'over-budget'}:
            gaps.add('package-metadata-' + metadata['metadata_status'])
        observed = repository is not None and repository.get('metadata_status') == 'observed'
        if requested is None: gaps.add('repository-unmapped')
        elif not observed: gaps.add('repository-not-found')
        version_time = metadata.get('version_timestamp')
        commit_time = None
        if observed:
            commit_time = repository['commits'].get(metadata.get('source_commit'))
            if ecosystem == 'github-actions': version_time = commit_time
            if metadata.get('release_tag'): version_time = repository['releases'].get(metadata['release_tag'])
            if repository['archived']: signals.add('repository-archived')
            if repository['disabled']: signals.add('repository-disabled')
        version_time, version_age, future = age(version_time, now)
        if future: signals.add('timestamp-in-future')
        if ecosystem != 'fixture':
            if version_time is None: gaps.add('version-timestamp-unavailable')
            if version_age is not None and version_age >= LIMITS['selected_version_age_days']:
                signals.add('selected-version-365-days-old')
        commit_time, _commit_age, commit_future = age(commit_time, now)
        if commit_future: signals.add('timestamp-in-future')
        if ecosystem == 'fixture' and metadata.get('source_commit') and commit_time is None:
            gaps.add('source-commit-timestamp-unavailable')
        push_time, push_age, push_future = age(repository['last_push'] if observed else None, now)
        if push_future: signals.add('timestamp-in-future')
        if observed and push_time is None: gaps.add('repository-push-timestamp-unavailable')
        if push_age is not None and push_age >= LIMITS['repository_no_push_days']:
            signals.add('repository-no-push-730-days')
        if metadata.get('deprecated') is True: signals.add('package-deprecated')
        if ecosystem == 'npm' and metadata.get('deprecated') is None: gaps.add('package-deprecation-unavailable')
        return {'ecosystem': ecosystem, 'name': name, 'version': version, 'origins': component['origins'],
                'selected_version_timestamp': version_time, 'selected_version_age_days': version_age,
                'source_commit_timestamp': commit_time, 'repository': requested,
                'canonical_repository': repository['canonical_repository'] if observed else None,
                'repository_last_push': push_time, 'repository_no_push_days': push_age,
                'package_deprecated': metadata.get('deprecated'),
                'review_signals': sorted(signals), 'metadata_gaps': sorted(gaps),
                'status': 'review' if signals else 'unknown' if gaps else 'no-listed-signal'}
    except (OSError, ValueError, KeyError, TypeError, AttributeError): raise MaintenanceError() from None


def metadata(components):
    result = {}; npm = defaultdict(list)
    for index, component in enumerate(components):
        key = identity(component); ecosystem, name, version = key
        row = {'metadata_status': 'inventory-version', 'repository': None,
               'version_timestamp': component.get('version_published_at'), 'deprecated': None,
               'source_commit': None, 'release_tag': None}
        if ecosystem == 'gomod':
            if name.startswith('github.com/') and row['version_timestamp'] is not None:
                row['repository'] = sources.actions.repository('/'.join(name.split('/')[1:3]))
            else:
                observation = sources.go_metadata(name, version)
                previous = sources.timestamp(row['version_timestamp'])
                current = sources.timestamp(observation['version_timestamp'])
                require(previous is None or observation['metadata_status'] != 'observed' or current == previous)
                row.update(observation)
                row['version_timestamp'] = previous or current
        elif ecosystem == 'npm': npm[name].append(version)
        elif ecosystem == 'pypi':
            observation = sources.pypi_metadata(name, version)
            row.update(observation); row['version_timestamp'] = component.get('version_published_at')
        elif ecosystem in {'fixture', 'github-actions'}:
            source = component['source']; candidate = source.get('repository')
            if candidate is not None:
                row['repository'] = sources.actions.repository(candidate)
            row['source_commit'] = source.get('commit')
            require(row['source_commit'] is None or sources.SHA.fullmatch(row['source_commit']))
        elif ecosystem == 'generic':
            if name == 'helm' and component['source']['url'].startswith('https://get.helm.sh/helm-'):
                row['repository'] = 'helm/helm'; row['release_tag'] = version
            elif name == 'oasdiff' and component['source']['url'].startswith('https://github.com/oasdiff/oasdiff/releases/download/'):
                tag = component['source']['url'].split('/releases/download/', 1)[1].split('/', 1)[0]
                require(tag in {version, 'v' + version} and sources.TAG.fullmatch(tag))
                row['repository'] = 'oasdiff/oasdiff'; row['release_tag'] = tag
        result[key] = row
        if index % 250 == 0: print('dependency-maintenance: source metadata ' + str(index + 1) + '/' + str(len(components)), flush=True)
    for index, name in enumerate(sorted(npm)):
        observations = sources.npm_package(name, sorted(npm[name]))
        for version, observation in observations.items(): result[('npm', name, version)].update(observation)
        if index % 25 == 0: print('dependency-maintenance: package metadata ' + str(index + 1) + '/' + str(len(npm)), flush=True)
    return result


def image_review(row, repositories):
    reference = row['reference']; repo = None
    if reference.startswith('ghcr.io/aatuh/evydence:'): repo = 'aatuh/evydence'
    elif reference.startswith('ghcr.io/ossf/scorecard-action:'): repo = 'ossf/scorecard-action'
    gaps = ['image-version-timestamp-unavailable']; signals = []
    observed = repositories.get(repo)
    if row['kind'] == 'operator-selected': gaps.append('operator-selected-image-unresolved')
    if repo is None: gaps.append('repository-unmapped')
    elif observed['metadata_status'] != 'observed': gaps.append('repository-not-found')
    else:
        if observed['archived']: signals.append('repository-archived')
        if observed['disabled']: signals.append('repository-disabled')
    if row.get('resolution', {}).get('mutable_reference'): signals.append('mutable-image-reference')
    return {'reference': reference, 'kind': row['kind'], 'repository': repo,
            'manifest_digest': row.get('observation', {}).get('manifest_digest'),
            'review_signals': sorted(signals), 'metadata_gaps': sorted(gaps)}


def summary(components, images, repositories):
    return {'components': len(components), 'images': len(images), 'repositories': len(repositories),
            'component_status': dict(sorted(Counter(row['status'] for row in components).items())),
            'review_signals': dict(sorted(Counter(signal for row in components for signal in row['review_signals']).items())),
            'metadata_gaps': dict(sorted(Counter(gap for row in components for gap in row['metadata_gaps']).items()))}


def collect(root, as_of=None):
    try:
        components, image_rows, frozen = inputs(root)
        observations = metadata(components)
        requests = {}
        for row in observations.values():
            repo = row['repository']
            if repo is None: continue
            request = requests.setdefault(repo, {'commits': set(), 'releases': set()})
            if row['source_commit']: request['commits'].add(row['source_commit'])
            if row['release_tag']: request['releases'].add(row['release_tag'])
        for row in image_rows:
            if row['reference'].startswith('ghcr.io/aatuh/evydence:'): requests.setdefault('aatuh/evydence', {'commits': set(), 'releases': set()})
            if row['reference'].startswith('ghcr.io/ossf/scorecard-action:'): requests.setdefault('ossf/scorecard-action', {'commits': set(), 'releases': set()})
        requests = {name: {key: sorted(values) for key, values in row.items()} for name, row in sorted(requests.items())}
        repositories = sources.repositories(requests) if requests else {}
        now = as_of or datetime.now(timezone.utc)
        reviewed = [review(row, observations[identity(row)], repositories.get(observations[identity(row)]['repository']), now) for row in components]
        image_reviews = [image_review(row, repositories) for row in image_rows]
        fresh_components, fresh_images, fresh = inputs(root)
        require(components == fresh_components and image_rows == fresh_images and frozen == fresh
                and all(read_bytes(root, name, inventory.MAX_BYTES) == raw for name, raw in frozen.items()))
        return {'schema': SCHEMA, 'as_of': now.isoformat(), 'thresholds': LIMITS,
                'scope': 'source-inventory-and-declared-images', 'maintenance_health_certified': False,
                'inputs': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(frozen.items())},
                'metadata': [{'ecosystem': key[0], 'name': key[1], 'version': key[2], **value} for key, value in sorted(observations.items())],
                'repositories': repositories, 'components': reviewed, 'images': image_reviews,
                'summary': summary(reviewed, image_reviews, repositories)}
    except (OSError, ValueError, KeyError, TypeError, AttributeError): raise MaintenanceError() from None


def check(root, report):
    try:
        require(isinstance(report, dict) and report.get('schema') == SCHEMA and report.get('thresholds') == LIMITS
                and report.get('scope') == 'source-inventory-and-declared-images' and report.get('maintenance_health_certified') is False)
        components, image_rows, frozen = inputs(root)
        require(report['inputs'] == {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(frozen.items())})
        now = datetime.fromisoformat(sources.timestamp(report['as_of']).replace('Z', '+00:00'))
        metadata_rows = report['metadata']; require(isinstance(metadata_rows, list) and len(metadata_rows) == len(components))
        observations = {identity(row): {key: value for key, value in row.items() if key not in {'ecosystem', 'name', 'version'}} for row in metadata_rows}
        require(set(observations) == {identity(row) for row in components})
        reviewed = [review(row, observations[identity(row)], report['repositories'].get(observations[identity(row)]['repository']), now) for row in components]
        image_reviews = [image_review(row, report['repositories']) for row in image_rows]
        require(report['components'] == reviewed and report['images'] == image_reviews
                and report['summary'] == summary(reviewed, image_reviews, report['repositories']))
    except (OSError, ValueError, KeyError, TypeError, AttributeError): raise MaintenanceError() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', default=REPORT)
    parser.add_argument('--replace', action='store_true')
    parser.add_argument('--check', action='store_true', help='Offline source binding and deterministic signal checks; no fresh provider observation.')
    args = parser.parse_args(argv); handlers = {}
    try:
        def interrupted(_signum, _frame): raise MaintenanceError()
        for signum in (signal.SIGTERM, signal.SIGINT): handlers[signum] = signal.signal(signum, interrupted)
        if args.check:
            check(args.root, policy.parse_document(read_bytes(args.root, args.output, inventory.MAX_BYTES)))
            print('dependency-maintenance: offline source binding and signal checks passed')
        else:
            directory, old = reports.directory(args.root, args.output, SCHEMA, args.replace); os.close(directory)
            report = collect(args.root); check(args.root, report)
            reports.write(args.root, args.output, report, SCHEMA, replace=args.replace, expected=old)
            print('dependency-maintenance: wrote ' + str(len(report['components'])) + ' component reviews')
        return 0
    except (OSError, ValueError, TypeError):
        print('dependency-maintenance: operation failed; existing reports preserved', file=sys.stderr); return 2
    finally:
        for signum, handler in handlers.items(): signal.signal(signum, handler)


if __name__ == '__main__': sys.exit(main())
