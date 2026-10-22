#!/usr/bin/env python3
"""Apply current-target policy to verified source-package component changes.

Call with fresh in-memory trusted collection results, never PR-supplied reports.
This partial source-package decision is not the final complete-scope CI verdict.
"""
import copy
import hashlib
import json
import re

import dependency_advisories as advisories
import dependency_collection as collection
import dependency_exception_reviews as exception_reviews
import dependency_git_objects as objects
import dependency_inventory as inventory
import dependency_policy as policy
import dependency_review_provider as provider

POLICY_PATH='release/dependency-policy.json'
SCHEMA='evydence-source-package-admission.v1'
MAX_COMPONENTS=8192
MAX_ROW_BYTES=512*1024
MAX_COMPONENT_BYTES=8*1024*1024
LICENSE_STATES={'candidate','artifact-declared','recorded-declaration'}


class AdmissionError(ValueError):
    def __init__(self):super().__init__('invalid or unverified source-package admission context')


def require(value):
    if not value:raise AdmissionError()


def base_rules(value,today):
    # Expiry disables an otherwise well-formed waiver. It must not prevent a
    # policy-cleanup PR from removing that waiver under the old trusted policy.
    policy.validate_policy({**value,'exceptions':[]},today)
    rows=value['exceptions'];require(isinstance(rows,list) and len(rows)<=128)
    active=[];expired=[];identities=set();scopes=set()
    for row in rows:
        reviewed=policy._day(row['reviewed_on'])
        policy.validate_policy({**value,'exceptions':[row]},reviewed)
        scope=policy._coordinates(row)+(row['kind'],row['value'])
        require(row['id'] not in identities and scope not in scopes)
        identities.add(row['id']);scopes.add(scope)
        if policy._day(row['expires_on'])<=today:expired.append(row['id'])
        else:active.append(row)
    return policy.validate_policy({**value,'exceptions':active},today),sorted(expired)


def load_policy(reader,current_target_base,today):
    """No head/merge-base fallback; Git identity is not independent review proof."""
    try:
        base=provider.sha(current_target_base);tree_id,tree=reader.tree(base);provider.sha(tree_id)
        row=tree[POLICY_PATH];require(row['type']=='blob' and row['mode'] in {'100644','100755'})
        identity=provider.sha(row['sha']);raw=reader.blob(identity)
        require(isinstance(raw,bytes) and len(raw)<=objects.MAX_BLOB_BYTES
                and objects.object_id('blob',raw)==identity)
        rules,expired=base_rules(policy.parse_document(raw),today)
        return rules,{'commit':base,'path':POLICY_PATH,'git_blob':identity,'sha256':hashlib.sha256(raw).hexdigest(),
                      'expired_exceptions':expired}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError):raise AdmissionError() from None


def component_rows(observation,source,base):
    require(isinstance(observation,dict) and observation.get('schema')==collection.SCHEMA
            and observation.get('source_bytes_verified') is True and observation.get('trusted_base')==base
            and observation.get('source',{}).get('commit')==source)
    snapshot=observation.get('inventory');require(isinstance(snapshot,dict) and snapshot.get('schema')==inventory.SCHEMA)
    rows=snapshot.get('components');require(isinstance(rows,list) and len(rows)<=MAX_COMPONENTS)
    result={};total=0
    for row in rows:
        require(isinstance(row,dict) and 'license' in row and isinstance(row.get('license_status'),str))
        coords=advisories.identity(row);key=tuple(coords.values());require(key not in result)
        origins=row.get('origins')
        require(isinstance(origins,list) and 0<len(origins)<=64 and all(
            isinstance(value,str) and re.fullmatch(r'[a-z][a-z0-9-]{0,63}',value) for value in origins)
            and len(set(origins))==len(origins))
        material={name:value for name,value in row.items() if name!='origins'}
        raw=json.dumps(material,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
        total+=len(raw);require(len(raw)<=MAX_ROW_BYTES and total<=MAX_COMPONENT_BYTES)
        effective=row['license'] if row['license_status'] in LICENSE_STATES else None
        result[key]={'component':{**coords,'license':effective},'origins':set(origins),
                     'source_sha256':hashlib.sha256(raw).hexdigest()}
    return result


def assess_changes(reader,current_target_base,comparison_base,head,before,after,api,today,*,review_api=None):
    """The trusted caller owns provider/source authentication and complete scope joins."""
    try:
        base=provider.sha(current_target_base);comparison_base=provider.sha(comparison_base);head=provider.sha(head)
        require(comparison_base!=head and base!=head)
        rules,selected=load_policy(reader,base,today)
        previous=component_rows(before,comparison_base,base);proposed=component_rows(after,head,base)
        changes=[]
        for identity,row in sorted(proposed.items()):
            old=previous.get(identity);added=row['origins']-(old['origins'] if old else set())
            if (old is not None and not added and row['source_sha256']==old['source_sha256']
                    and identity not in getattr(api,'required_components',set())):continue
            value=row['component'];observation=api.observe(value)
            require(isinstance(observation,dict) and observation.get('component')==advisories.identity(value)
                    and observation.get('status') in {'observed','unsupported','unavailable'})
            vulnerabilities=observation.get('vulnerabilities')
            if observation['status']=='observed':
                result=policy.assess_component({**value,'vulnerabilities':vulnerabilities},rules,today)
            else:
                require(vulnerabilities is None)
                result={'passed':False,'violations':['advisory_coverage_unknown'],'exceptions':[]}
            changes.append({**value,'change_type':'added' if old is None else 'changed',
                            'added_origins':sorted(added),'source_sha256':row['source_sha256'],
                            'previous_source_sha256':None if old is None else old['source_sha256'],
                            'advisory_status':observation['status'],'vulnerabilities':copy.deepcopy(vulnerabilities),**result})
        removed=[advisories.identity(previous[key]['component']) for key in sorted(set(previous)-set(proposed))]
        used={identifier for row in changes for identifier in row['exceptions']}
        applicable={**rules,'exceptions':[row for row in rules['exceptions'] if row['id'] in used]}
        approvals=exception_reviews.verify(applicable,review_api,today)
        require(exception_reviews.verify(applicable,review_api,today)==approvals)
        return {'schema':SCHEMA,'current_target_base':base,'comparison_base':comparison_base,'head':head,
                'policy':selected,'changes':changes,'removed':removed,
                'exception_reviews':approvals,
                'package_decision_passed':all(row['passed'] for row in changes),
                'dependency_coverage_verified':False,'advisory_receipts':copy.deepcopy(api.receipts)}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError):raise AdmissionError() from None
