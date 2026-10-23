#!/usr/bin/env python3
"""Bind inert test-data applicability to trusted collection and original Git bytes."""
import hashlib
from pathlib import PurePosixPath
import re

import dependency_advisories as advisories
import dependency_collection as collection
import dependency_git_objects as objects
import dependency_inputs as inputs
import dependency_policy as policy
import dependency_review_provider as provider
import fixture_provenance as provenance


class FixtureError(ValueError):
    def __init__(self):super().__init__('invalid or unsupported immutable data-fixture applicability')


def require(value):
    if not value:raise FixtureError()


def observe(reader,observed,row):
    """Use fresh trusted collection rows, never a proposed saved report or label."""
    try:
        require(observed.get('schema')==collection.SCHEMA and observed.get('source_bytes_verified') is True)
        source=observed['source'];commit=provider.sha(source['commit']);tree_id,tree=reader.tree(commit)
        require(source['tree']==tree_id)
        listed=source['files'];require(isinstance(listed,list) and len(listed)<=inputs.MAX_INPUT_FILES)
        by_path={item['path']:item for item in listed};require(len(by_path)==len(listed))
        require(isinstance(row,dict) and advisories.identity(row)['ecosystem']=='fixture'
                and row['origins']==['fixtures'] and row['license_status']=='recorded-declaration'
                and isinstance(row['version'],str) and re.fullmatch(r'[0-9a-f]{64}',row['version']))
        components=observed['inventory']['components']
        require(isinstance(components,list) and len(components)<=8192 and components.count(row)==1)
        record=row['source'];require(record['verification']=='local-digests-checked'
                and record['kind'] in {'bytes','json','markdown-json','project','recorded-generated'})
        total=0
        def read(item):
            nonlocal total
            name=provider.git_path(item['path']);entry=tree[name];frozen=by_path[name]
            require(entry['type']=='blob' and entry['mode']=='100644' and frozen['mode']==entry['mode']
                    and frozen['git_blob']==entry['sha'] and frozen['sha256']==item['sha256']
                    and observed['inventory']['inputs'][name]==item['sha256'])
            raw=reader.blob(provider.sha(entry['sha']))
            require(isinstance(raw,bytes) and len(raw)<=objects.MAX_BLOB_BYTES
                    and type(frozen['bytes']) is int and len(raw)==frozen['bytes']
                    and objects.object_id('blob',raw)==entry['sha']
                    and hashlib.sha256(raw).hexdigest()==item['sha256'])
            total+=len(raw);require(total<=provenance.MAX_TOTAL_BYTES)
            return raw,{'path':name,'git_blob':entry['sha'],'sha256':item['sha256']}
        files=record['files'];require(isinstance(files,list) and 0<len(files)<=64)
        names=set();parts=[];proof=[]
        for item in files:
            name=provider.git_path(item['path'])
            require(name not in names and inputs.fixture_payload(name)
                    and PurePosixPath(name).suffix in {'.json','.fragment','.txt'})
            names.add(name);raw,binding=read(item)
            text=raw.decode('utf-8-sig')
            require(not raw.startswith((b'\x7fELF',b'MZ',b'PK\x03\x04',b'\x1f\x8b'))
                    and all(char in '\t\r\n' or ord(char)>=32 and ord(char)!=127 for char in text)
                    and not text.lstrip().startswith('#!'))
            parts.append(raw);proof.append(binding)
        require(hashlib.sha256(b''.join(parts)).hexdigest()==row['version'])
        notices=row['license_notices'];identities=record['notices']
        require(isinstance(notices,list) and 0<len(notices)<=16 and isinstance(identities,list)
                and len(identities)==len(set(identities)) and len(notices)==len(identities)
                and {item['id'] for item in notices}==set(identities)
                and any(item['license']==row['license'] for item in notices))
        for item in notices:
            provenance.notice_path(item['path']);read(item)
        return {'component':advisories.identity(row),'status':'not-applicable-data-fixture',
                'profile':'utf8-test-data.v1','vulnerabilities':None,'source_commit':commit,
                'files':proof,'notice_count':len(notices)}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise FixtureError() from None


def assess_license(component,rules,today):
    """A non-package data profile still uses the canonical license/waiver rules."""
    rules=policy.validate_policy(rules,today);coordinates=policy._coordinates(component)
    expression=component['license'];violations=[];matched=[]
    if not policy.license_allowed(expression,rules):
        unknown=expression is None or expression.strip().upper() in policy.UNKNOWN_LICENSES
        target='NOASSERTION' if unknown else expression
        matched=[row['id'] for row in rules['exceptions'] if policy._coordinates(row)==coordinates
                 and row['kind']=='license' and row['value']==target]
        if not matched:violations.append('unknown_license' if unknown else 'disallowed_license')
    return {'passed':not violations,'violations':violations,'exceptions':sorted(matched)}
