#!/usr/bin/env python3
"""Join authenticated dependency-review findings with exact source-package data."""
import copy
import re

import dependency_admission as admission
import dependency_advisories as advisories
import dependency_comparison as comparison
import dependency_policy as policy
import dependency_review_provider as provider


class JoinError(ValueError):
    def __init__(self):super().__init__('invalid exact-source dependency-provider join')


def require(value):
    if not value:raise JoinError()


def identity(value):
    result=advisories.identity(value)
    if result['ecosystem']=='pypi':result['name']=re.sub(r'[-_.]+','-',result['name']).lower()
    return tuple(result.values())


def license_tokens(value):
    if value is None or isinstance(value,str) and value.strip().upper() in policy.UNKNOWN_LICENSES:return None
    parser=policy._Expression(value,set(),set());parser.evaluate()
    return tuple(token.casefold() for token in parser.tokens)


class JoinedAdvisories:
    def __init__(self,snapshot,source_rows,api,base,merge,head):
        require(isinstance(snapshot,dict) and snapshot.get('schema')==provider.SCHEMA
                and snapshot.get('repository')==provider.REPOSITORY and snapshot.get('base')==base
                and snapshot.get('comparison_base')==merge and snapshot.get('head')==head
                and snapshot.get('provider_authenticated') is True and snapshot.get('file_listing_verified') is True)
        values=snapshot.get('dependency_rows');require(isinstance(values,list) and len(values)<=comparison.MAX_ROWS)
        self.api=api;self.snapshot=snapshot;self.rows={};self.required_components=set();self.conflicts=set()
        canonical={}
        for key,row in source_rows.items():
            normalized=identity(row['component']);require(normalized not in canonical);canonical[normalized]=key
        seen=set()
        for row in values:
            value=comparison.component(row);manifest=comparison.manifest(row.get('manifest'));key=identity(value)
            observation=(key,manifest,row['change_type']);require(observation not in seen);seen.add(observation)
            if row['change_type']=='removed':continue
            if key not in self.rows:self.rows[key]={'component':value,'manifests':set(),'licenses':set(),'findings':{}}
            entry=self.rows[key];entry['manifests'].add(manifest)
            license=license_tokens(value['license'])
            if license is not None:entry['licenses'].add(license)
            for finding in value['vulnerabilities']:
                previous=entry['findings'].get(finding['id'])
                if previous is None or advisories.SEVERITIES[finding['severity']]>advisories.SEVERITIES[previous['severity']]:
                    entry['findings'][finding['id']]=finding
            if key in canonical:self.required_components.add(canonical[key])
        self.unmatched=[{**entry['component'],'vulnerabilities':[entry['findings'][identifier] for identifier in sorted(entry['findings'])],
                         'manifests':sorted(entry['manifests'])} for key,entry in sorted(self.rows.items()) if key not in canonical]

    @property
    def receipts(self):return [*copy.deepcopy(self.api.receipts),*copy.deepcopy(self.snapshot.get('receipts',[]))]

    def observe(self,component):
        result=copy.deepcopy(self.api.observe(component));require(result.get('component')==advisories.identity(component))
        key=identity(component);entry=self.rows.get(key)
        if entry is None:return result
        actual=license_tokens(component['license'])
        if len(entry['licenses'])>1 or actual is not None and any(value!=actual for value in entry['licenses']):self.conflicts.add(key)
        # Only an explicit recognized Action row supplies the supported GitHub
        # advisory profile. A failed OSV query is never replaced with an empty list.
        if result['status']=='unsupported' and component['ecosystem']=='github-actions':
            require(result['vulnerabilities'] is None)
            result.update(status='observed',vulnerabilities=[])
        if result['status']=='observed':
            policy._component({**advisories.identity(component),'license':component['license'],
                               'vulnerabilities':result['vulnerabilities']})
            findings={row['id']:row for row in result['vulnerabilities']}
            for identifier,finding in entry['findings'].items():
                previous=findings.get(identifier)
                if previous is None or advisories.SEVERITIES[finding['severity']]>advisories.SEVERITIES[previous['severity']]:findings[identifier]=finding
            result['vulnerabilities']=[findings[identifier] for identifier in sorted(findings)]
        result['github_manifests']=sorted(entry['manifests'])
        return result


def assess(reader,base,merge,head,before,after,snapshot,api,today,*,review_api=None):
    try:
        for value in [base,merge,head]:provider.sha(value)
        rows=admission.component_rows(after,head,base)
        joined=JoinedAdvisories(snapshot,rows,api,base,merge,head)
        result=admission.assess_changes(reader,base,merge,head,before,after,joined,today,review_api=review_api)
        for row in result['changes']:
            entry=joined.rows.get(identity(row))
            row['provider_findings']=[] if entry is None else [entry['findings'][key] for key in sorted(entry['findings'])]
            if identity(row) in joined.conflicts:
                row['violations'].append('provider_license_conflict');row['passed']=False
        result['provider_join_passed']=not joined.unmatched and not joined.conflicts
        result['unmatched_provider_components']=joined.unmatched
        result['package_decision_passed']=result['provider_join_passed'] and all(row['passed'] for row in result['changes'])
        result['provider_context']={key:snapshot[key] for key in ['repository','base','comparison_base','head']}
        return result
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise JoinError() from None
