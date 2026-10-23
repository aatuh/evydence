#!/usr/bin/env python3
"""Assess bundled Go packages in changed checksum-pinned QA tool artifacts."""
import copy
from pathlib import Path
import re
import tempfile

import dependency_admission as admission
import dependency_advisories as advisories
import dependency_build_tools as build_tools
import dependency_exception_reviews as reviews
import dependency_fixture_advisories as licenses
import dependency_inventory as inventory
import dependency_tool_buildinfo as buildinfo
import dependency_tool_sources as sources
from release_lifecycle import read_bytes

PROFILE='checksum-bound-go-tool-linux-amd64.v1'
MAIN={'helm':'helm.sh/helm/v4','oasdiff':'github.com/oasdiff/oasdiff'}


class ToolAdmissionError(ValueError):
    def __init__(self):super().__init__('invalid or incomplete checksum-bound Go tool admission')


def require(value):
    if not value:raise ToolAdmissionError()


class Client:
    def __init__(self,api,observed,base,head,work_root,parent,classifier,reader,today,*,review_api=None):
        try:
            admission.component_rows(observed,head,base)
            require(classifier.receipt['trusted_base']==base)
            self.rules,self.policy=admission.load_policy(reader,base,today)
            self.api=api;self.work_root=Path(work_root);self.parent=parent;self.classifier=classifier
            self.today=today;self.review_api=review_api;self.sources=None;self.cache={};self.artifacts=[];self.changes=[];self.approvals=[]
            self.rows={tuple(advisories.identity(row).values()):row for row in observed['inventory']['components'] if row['ecosystem']=='generic'}
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ToolAdmissionError() from None

    @property
    def receipts(self):return self.api.receipts

    def observe_query(self,component,query):return self.api.observe_query(component,query)

    def package(self,value,root,*,stdlib=None):
        component={**advisories.identity(value),'license':value['license'] if value['license_status'] in admission.LICENSE_STATES else None}
        if stdlib:
            component.update(name='stdlib',version=stdlib)
            result=self.api.observe_query(component,{'package':{'ecosystem':'Go','name':'stdlib'},'version':stdlib[2:]})
        else:result=self.api.observe(component)
        require(result.get('component')==advisories.identity(component) and result.get('status') in {'observed','unsupported','unavailable'})
        if result['status']=='observed':decision=admission.policy.assess_component({**component,'vulnerabilities':result['vulnerabilities']},self.rules,self.today)
        else:
            require(result.get('vulnerabilities') is None)
            decision=licenses.assess_license(component,self.rules,self.today)
            decision['passed']=False;decision['violations'].append('advisory_coverage_unknown')
        self.changes.append({**component,'tool':root,'source':copy.deepcopy(value['source']),
            'license_status':value['license_status'],'license_evidence':copy.deepcopy(value['license_evidence']),
            'advisory_status':result['status'],'vulnerabilities':copy.deepcopy(result['vulnerabilities']),**decision})
        require(len(self.changes)<=admission.MAX_COMPONENTS)

    def applicable(self):
        used={identifier for row in self.changes for identifier in row['exceptions']}
        return {**self.rules,'exceptions':[row for row in self.rules['exceptions'] if row['id'] in used]}

    def observe(self,component):
        try:
            identity=advisories.identity(component)
            if identity['ecosystem']!='generic':return self.api.observe(component)
            key=tuple(identity.values());require(key in self.rows)
            if key in self.cache:return copy.deepcopy(self.cache[key])
            row=self.rows[key];require(row['name'] in MAIN and row['source']['verification']=='sha256-verified')
            work=Path(tempfile.mkdtemp(prefix='dependency-tool-artifact-',dir=self.work_root))
            observation,files=build_tools.fetch(row,work)
            require(observation['binary_sha256']==row['source']['binary_sha256'])
            classified=inventory.attach_licenses(row,files,self.classifier.classify(files))
            effective=classified['license'] if classified['license_status'] in admission.LICENSE_STATES else None
            require(effective==component['license'])
            raw=read_bytes(work,row['source']['sha256']+'.tar.gz',build_tools.MAX_ARCHIVE_BYTES)
            artifact=buildinfo.inspect(raw,row,work,self.parent,self.classifier.receipt['go_version'])
            require(artifact['archive_sha256']==row['source']['sha256'] and artifact['binary_sha256']==row['source']['binary_sha256'])
            metadata=artifact['buildinfo'];main=metadata['main'];compiler=metadata['go_version']
            require(main['name']==MAIN[row['name']] and main['version']=='v'+row['version'].removeprefix('v') and main['replacement'] is None
                    and metadata['platform']=={'goos':'linux','goarch':'amd64','cgo_enabled':False}
                    and isinstance(compiler,str) and re.fullmatch(r'go[1-9][0-9]*\.[0-9]+\.[0-9]+',compiler))
            module={'ecosystem':'gomod','name':main['name'],'version':main['version']}
            result=copy.deepcopy(self.api.observe(module));require(result.get('component')==module
                and result.get('status') in {'observed','unsupported','unavailable'})
            result.update(component=identity,profile=PROFILE)
            if self.sources is None:self.sources=sources.Sources(self.work_root,self.parent,self.classifier)
            for entry in metadata['modules']:
                require(entry['replacement'] is None and entry['version'] is not None and entry['sum'] is not None)
                self.package(self.sources.resolve(entry['name'],entry['version'],entry['sum']),identity)
            self.package(self.sources.resolve('golang.org/toolchain','v0.0.1-'+compiler+'.linux-amd64',None),identity,stdlib=compiler)
            self.artifacts.append({'component':identity,**artifact})
            approvals=reviews.verify(self.applicable(),self.review_api,self.today)
            require({proof['exception_id'] for proof in approvals}=={row['id'] for row in self.applicable()['exceptions']})
            require(all(proof in approvals for proof in self.approvals));self.approvals=approvals
            self.verify();self.cache[key]=copy.deepcopy(result);return result
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ToolAdmissionError() from None

    def verify(self):
        try:
            self.classifier.verify()
            require(reviews.verify(self.applicable(),self.review_api,self.today)==self.approvals)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ToolAdmissionError() from None

    def evidence(self):
        return {'schema':'evydence-tool-admission.v1','profile':PROFILE,'scope':'changed-pinned-tool-artifacts',
            'policy':self.policy,'artifacts':copy.deepcopy(self.artifacts),'package_changes':copy.deepcopy(self.changes),
            'exception_reviews':copy.deepcopy(self.approvals),'tool_coverage_verified':True,
            'tool_decision_passed':all(row['passed'] for row in self.changes),
            'complete_artifact_sbom':False,'binary_source_equivalence_verified':False}
