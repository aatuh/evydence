#!/usr/bin/env python3
"""Qualify the declared change-admission profile, separately from artifact completeness."""
from collections import Counter
import hashlib

import dependency_admission as admission
import dependency_classifier as classifiers
import dependency_collection as collection
import dependency_git_objects as objects
import dependency_inputs as inputs
import dependency_inventory as inventory

PROFILE='declared-dependency-changes-linux-amd64.v1'
REQUIRED_INPUTS={inventory.fixture_sources.CATALOG,'release/support-matrix.json','tools/requirements-qa.txt',
    'site/marketing/package.json','site/marketing/package-lock.json',*inventory.go_tools.INPUTS,
    *(name for _scope,mod,sums,_main in inventory.GRAPHS for name in (mod,sums))}
REQUIRED_SCHEMAS={'fixture-file-coverage-and-hashes','npm-lock','python-qa-pins','standalone-go-installation-bindings'}
SOURCES={
    'gomod':('go-mod-verify',{row[0] for row in inventory.GRAPHS}|set(inventory.go_tools.SCOPES)|{'scanner-tool'}),
    'npm':('sha512-verified',{'marketing'}),'pypi':('sha256-verified',{'qa'}),
    'fixture':('local-digests-checked',{'fixtures'}),'generic':('sha256-verified',{'qa-tool'}),
    'github-actions':('github-git-objects',{'ci','workflow-example','action-dependency'}),
}


class CoverageError(ValueError):
    def __init__(self):super().__init__('invalid or unbound declared dependency coverage profile')


def require(value):
    if not value:raise CoverageError()


def source_profile(reader,value,source,base,receipt,code):
    """Only called on fresh trusted in-memory collections, never saved PR reports."""
    try:
        admission.component_rows(value,source,base)
        frozen,contents=inputs.revision(reader,source)
        require(frozen==value['source']);collection.verified_contents(frozen,contents,source)
        require(REQUIRED_SCHEMAS<=set(frozen['schemas_verified']))
        snapshot=value['inventory'];generator=snapshot['generator']
        require(snapshot.get('complete') is False and REQUIRED_INPUTS<=set(snapshot['inputs'])
            and all(name in contents and hashlib.sha256(contents[name]).hexdigest()==digest for name,digest in snapshot['inputs'].items()))
        require(receipt['schema']==classifiers.SCHEMA and receipt['trusted_base']==base
            and generator['classifier']==receipt and generator['go_version']==receipt['go_version'])
        require(value['trusted_driver_files']=={name:hashlib.sha256(code[name]).hexdigest() for name in collection.DRIVER_FILES})
        expected={name:hashlib.sha256(code[name]).hexdigest() if name.endswith('.py') else receipt['sources'][name]['sha256']
                  for name in inventory.GENERATOR_FILES}
        require(generator['files']==expected)
        remaining=snapshot.get('remaining_scopes')
        require(isinstance(remaining,list) and 'images' in remaining and len(remaining)==len(set(remaining))
            and all(scope in {'images','action-local-references'} for scope in remaining))
        gaps=['source:'+scope for scope in remaining if scope!='images'];counts=Counter()
        for row in snapshot['components']:
            ecosystem=row['ecosystem'];counts[ecosystem]+=1
            if ecosystem not in SOURCES:gaps.append('source:unsupported-ecosystem:'+ecosystem);continue
            verification,origins=SOURCES[ecosystem]
            require(row['source'].get('verification')==verification)
            for origin in set(row['origins'])-origins:gaps.append('source:unsupported-origin:'+ecosystem+':'+origin)
        return {'profile':PROFILE,'source_commit':source,'trusted_base':base,
            'source_coverage_verified':not gaps,'coverage_gaps':sorted(set(gaps)),
            'component_counts':dict(sorted(counts.items())),'input_count':len(frozen['files']),
            'inventory_complete':False,'complete_artifact_sbom':False}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise CoverageError() from None


def combine(sources,image,tool):
    try:
        require(isinstance(sources,list) and len(sources)==2)
        gaps=[]
        for index,source in enumerate(sources):
            gaps.extend(source['coverage_gaps'])
            if source.get('source_coverage_verified') is not True:gaps.append('source-profile:'+str(index))
        gaps.extend('images:'+gap for gap in image['coverage_gaps'])
        if image.get('image_coverage_verified') is not True:gaps.append('image-profile')
        if tool.get('tool_coverage_verified') is not True:gaps.append('build-tool-profile')
        require(all(isinstance(gap,str) and 0<len(gap)<=2048 for gap in gaps))
        return {'schema':'evydence-dependency-admission-coverage.v1','profile':PROFILE,
            'source_profiles':sources,'coverage_gaps':sorted(set(gaps)),'dependency_coverage_verified':not gaps,
            'scope':'declared-source-and-artifact-dependency-changes','complete_artifact_sbom':False}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise CoverageError() from None
