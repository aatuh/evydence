#!/usr/bin/env python3
"""Bind pinned Action commits to full release tags and GitHub advisory queries."""
import copy
from datetime import datetime,timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
from urllib.parse import parse_qs,urlencode,urlsplit
from urllib.request import parse_http_list

import dependency_actions as sources
import dependency_admission as admission
import dependency_advisories as advisories
import dependency_policy as policy
import dependency_review_provider as provider
from release_scanner import capture

ROOT=Path(__file__).resolve().parents[1]
PROFILE='github-action-commit-release-tags.v1'
MAX_REQUESTS=256
MAX_RESPONSE_BYTES=4*1024*1024
MAX_TOTAL_BYTES=32*1024*1024
MAX_PAGES=20
MAX_VERSIONS=32
PER_PAGE=100
ADVISORY_TYPES=('reviewed','unreviewed','malware')
FULL_VERSION='v?'+advisories.SEMVER


class ActionAdvisoryError(ValueError):
    def __init__(self):super().__init__('invalid or unavailable bounded Action advisory binding')


def require(value):
    if not value:raise ActionAdvisoryError()


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def _capture_api(endpoint,*,include=False):
    environment={key:os.environ[key] for key in ('PATH','HOME','GH_TOKEN','GITHUB_TOKEN') if key in os.environ}
    environment.update(GH_PROMPT_DISABLED='1',GH_PAGER='cat',LC_ALL='C.UTF-8')
    arguments=['gh','api','--hostname','github.com','--method','GET',
        '-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10','-H','Accept-Encoding: identity']
    if include:arguments.append('--include')
    return capture([*arguments,endpoint],ROOT,environment,MAX_RESPONSE_BYTES,30)


def api(repo,page):
    try:
        repo=sources.repository(repo);require(page is None or type(page) is int and 1<=page<=MAX_PAGES)
        endpoint='repos/'+repo+('' if page is None else '/tags?per_page='+str(PER_PAGE)+'&page='+str(page))
        return _capture_api(endpoint)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ActionAdvisoryError() from None


def query_version(request):
    try:
        require(isinstance(request,dict) and set(request)=={'package','version'})
        package=request['package'];require(isinstance(package,dict) and set(package)=={'ecosystem','name'}
            and package['ecosystem']=='GitHub Actions')
        repo=sources.repository(package['name']);version=request['version']
        require(repo==package['name'] and isinstance(version,str) and len(version)<=128 and re.fullmatch(FULL_VERSION,version))
        return repo,version
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ActionAdvisoryError() from None


def filters(repo,version,kind):
    return {'ecosystem':'actions','affects':repo+'@'+version,'type':kind,'is_withdrawn':'false',
            'per_page':str(PER_PAGE),'sort':'published','direction':'asc'}


def advisory_api(repo,version,kind,cursor):
    try:
        repo,version=query_version({'package':{'ecosystem':'GitHub Actions','name':repo},'version':version})
        require(kind in ADVISORY_TYPES);parameters=filters(repo,version,kind)
        if cursor is not None:parameters['after']=advisories.token(cursor)
        return _capture_api('advisories?'+urlencode(parameters),include=True)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ActionAdvisoryError() from None


class Tags:
    def __init__(self,*,query=api):
        self.query=query;self.count=0;self.total=0;self.receipts=[];self.repositories={};self.bindings={};self.rechecks=[]

    def request(self,repo,page):
        self.count+=1;require(self.count<=MAX_REQUESTS)
        raw=self.query(repo,page)
        require(isinstance(raw,bytes) and len(raw)<=MAX_RESPONSE_BYTES)
        self.total+=len(raw);require(self.total<=MAX_TOTAL_BYTES)
        value=policy.parse_document(raw);index=len(self.receipts)
        self.receipts.append({'repository':repo,'endpoint':'repository' if page is None else 'tags',
                             'page':page,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        return value,index

    def read(self,repo):
        try:
            repo=sources.repository(repo);records={};indexes=[]
            metadata,index=self.request(repo,None)
            require(isinstance(metadata,dict) and metadata.get('private') is False
                    and isinstance(metadata.get('full_name'),str) and metadata['full_name'].lower()==repo)
            indexes.append(index)
            for page in range(1,MAX_PAGES+1):
                rows,index=self.request(repo,page);require(isinstance(rows,list) and len(rows)<=PER_PAGE)
                indexes.append(index)
                for row in rows:
                    require(isinstance(row,dict));name=row.get('name');commit=row.get('commit')
                    require(isinstance(name,str) and 0<len(name)<=256 and name not in records and isinstance(commit,dict))
                    identity=provider.sha(commit.get('sha'));url=commit.get('url')
                    require(isinstance(url,str) and url.lower()=='https://api.github.com/repos/'+repo+'/commits/'+identity)
                    records[name]=identity
                if len(rows)<PER_PAGE:return records,indexes
            raise ActionAdvisoryError()
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ActionAdvisoryError() from None

    def select(self,records,commit):
        values=[]
        for name,identity in records.items():
            if identity==commit and re.fullmatch(FULL_VERSION,name):
                require(len(name)<=128);values.append({'tag':name,'version':name})
        require(len(values)<=MAX_VERSIONS)
        return sorted(values,key=lambda row:row['tag'])

    def versions(self,repo,commit):
        repo=sources.repository(repo);commit=provider.sha(commit);key=repo,commit
        if repo not in self.repositories:self.repositories[repo]=self.read(repo)
        records,indexes=self.repositories[repo];tags=self.select(records,commit)
        self.bindings[key]={'repository':repo,'commit':commit,'tags':tags,'versions':sorted({row['version'] for row in tags}),
                            'binding_sha256':digest(tags),'receipt_indexes':indexes}
        return copy.deepcopy(self.bindings[key]['versions'])

    def verify(self):
        checked={};proof=[]
        for (repo,commit),previous in sorted(self.bindings.items()):
            if repo not in checked:checked[repo]=self.read(repo)
            records,indexes=checked[repo];tags=self.select(records,commit)
            require(tags==previous['tags'])
            proof.append({'repository':repo,'commit':commit,'binding_sha256':digest(tags),'receipt_indexes':indexes})
        self.rechecks=proof


class Advisories:
    def __init__(self,*,query=advisory_api):self.query=query;self.count=0;self.total=0;self.receipts=[]

    def request(self,repo,version,kind,cursor):
        self.count+=1;require(self.count<=MAX_REQUESTS)
        raw=self.query(repo,version,kind,cursor)
        require(isinstance(raw,bytes) and len(raw)<=MAX_RESPONSE_BYTES)
        self.total+=len(raw);require(self.total<=MAX_TOTAL_BYTES)
        stream=io.BytesIO(raw);status=stream.readline(129)
        require(re.fullmatch(rb'HTTP/(?:1\.[01]|2\.0) 200(?: [^\r\n]*)?\r?\n',status))
        headers=http.client.parse_headers(stream);require(stream.tell()<=64*1024)
        require(len(headers.get_all('Content-Type',[]))==1
                and headers.get_content_type() in {'application/json','application/vnd.github+json'})
        require(headers.get_all('Content-Encoding',[]) in [[],['identity']])
        body=stream.read();rows=policy.parse_document(body)
        require(isinstance(rows,list) and len(rows)<=PER_PAGE)
        index=len(self.receipts)
        self.receipts.append({'repository':repo,'version':version,'advisory_type':kind,'endpoint':'advisories',
            'cursor_sha256':None if cursor is None else hashlib.sha256(cursor.encode()).hexdigest(),
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'format':'gh-included-http-response'})
        following=None
        for entry in parse_http_list(','.join(headers.get_all('Link',[]))):
            match=re.fullmatch(r'<([^>]{1,8192})>;\s*rel="(next|prev|first|last)"',entry)
            require(match is not None)
            if match[2]!='next':continue
            require(following is None)
            target=urlsplit(match[1]);require(target.scheme=='https' and target.netloc=='api.github.com'
                and target.path=='/advisories' and not target.fragment)
            parameters=parse_qs(target.query,strict_parsing=True,encoding='utf-8',errors='strict',max_num_fields=12)
            expected=filters(repo,version,kind)
            require(set(parameters)==set(expected)|{'after'} and all(parameters[key]==[value] for key,value in expected.items())
                    and len(parameters['after'])==1)
            following=advisories.token(parameters['after'][0])
        return rows,following,index

    def observe_query(self,component,request):
        coords=advisories.identity(component);repo,version=query_version(request)
        require(coords['ecosystem']=='github-actions' and coords['name']==repo)
        result={'component':coords,'status':'unavailable','vulnerabilities':None,'withdrawn':[],
                'observed_at':datetime.now(timezone.utc).isoformat(),'receipt_indexes':[]}
        start=len(self.receipts)
        try:
            findings={};withdrawn=set()
            for kind in ADVISORY_TYPES:
                cursor=None;tokens=set();seen=set()
                for page in range(MAX_PAGES):
                    rows,following,_index=self.request(repo,version,kind,cursor)
                    for row in rows:
                        require(isinstance(row,dict));identifier=row.get('ghsa_id')
                        require(isinstance(identifier,str) and identifier.startswith('GHSA-')
                                and policy.ADVISORY.fullmatch(identifier) and identifier not in seen and row.get('type')==kind)
                        seen.add(identifier);require(len(seen)<=advisories.MAX_FINDINGS)
                        affected=row.get('vulnerabilities');require(isinstance(affected,list) and 0<len(affected)<=512)
                        require(any(isinstance(value,dict) and isinstance(value.get('package'),dict)
                            and value['package'].get('ecosystem')=='actions'
                            and isinstance(value['package'].get('name'),str) and value['package']['name'].lower()==repo for value in affected))
                        if row.get('withdrawn_at') is not None:
                            advisories.timestamp(row['withdrawn_at']);withdrawn.add(identifier);continue
                        severity=row.get('severity');severity=severity.lower() if isinstance(severity,str) else 'unknown'
                        severity='moderate' if severity=='medium' else severity if severity in advisories.SEVERITIES else 'unknown'
                        previous=findings.get(identifier)
                        if previous is None or advisories.SEVERITIES[severity]>advisories.SEVERITIES[previous['severity']]:
                            findings[identifier]={'id':identifier,'severity':severity}
                        require(len(findings)<=advisories.MAX_FINDINGS)
                    if following is None:break
                    require(following not in tokens and page+1<MAX_PAGES);tokens.add(following);cursor=following
                else:raise ActionAdvisoryError()
            result.update(status='observed',vulnerabilities=[findings[key] for key in sorted(findings)],withdrawn=sorted(withdrawn))
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,http.client.HTTPException):pass
        result['receipt_indexes']=list(range(start,len(self.receipts)));return result


class Client:
    def __init__(self,api,observed,base,source,*,tags=None,action_api=None):
        try:
            admission.component_rows(observed,provider.sha(source),provider.sha(base))
            self.api=api;self.tags=Tags() if tags is None else tags;self.rows={};self.cache={};self.queries={}
            self.action_api=Advisories() if action_api is None else action_api
            for row in observed['inventory']['components']:
                if row['ecosystem']!='github-actions':continue
                coords=advisories.identity(row);repo,path,commit=sources.external(coords['name']+'@'+coords['version'])
                record=row['source'];require(record['verification']=='github-git-objects' and record['repository']==repo
                    and record['path']==path and record['commit']==commit)
                provider.sha(record['root_tree']);key=tuple(coords.values())
                require(key not in self.rows and len(self.rows)<sources.MAX_COMPONENTS);self.rows[key]=(repo,commit)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ActionAdvisoryError() from None

    @property
    def receipts(self):return self.api.receipts

    def observe_query(self,component,query):return self.api.observe_query(component,query)

    def observe(self,component):
        coords=advisories.identity(component)
        if coords['ecosystem']!='github-actions':return self.api.observe(component)
        key=tuple(coords.values());require(key in self.rows)
        if key in self.cache:return copy.deepcopy(self.cache[key])
        repo,commit=self.rows[key]
        result={'component':coords,'status':'unsupported','vulnerabilities':None,'withdrawn':[],
                'profile':PROFILE,'repository':repo,'source_commit':commit,'release_versions':[],
                'observed_at':datetime.now(timezone.utc).isoformat(),'advisory_receipt_indexes':[]}
        try:
            versions=self.tags.versions(repo,commit);result['release_versions']=versions
            findings={};withdrawn=set();indexes=set()
            for version in versions:
                root={'ecosystem':'github-actions','name':repo,'version':commit};identity=repo,commit,version
                query={'package':{'ecosystem':'GitHub Actions','name':repo},'version':version}
                query_version(query)
                if identity not in self.queries:self.queries[identity]=copy.deepcopy(self.action_api.observe_query(root,query))
                value=self.queries[identity]
                require(value.get('component')==root and value.get('status')=='observed')
                policy._component({**root,'license':None,'vulnerabilities':value['vulnerabilities']})
                require(isinstance(value.get('withdrawn'),list) and len(value['withdrawn'])<=advisories.MAX_FINDINGS
                        and all(isinstance(item,str) and len(item)<=128 for item in value['withdrawn']))
                withdrawn.update(value['withdrawn']);indexes.update(value['receipt_indexes'])
                for finding in value['vulnerabilities']:
                    identifier=finding['id'];previous=findings.get(identifier)
                    if previous is None or advisories.SEVERITIES[finding['severity']]>advisories.SEVERITIES[previous['severity']]:findings[identifier]=finding
                require(len(findings)<=advisories.MAX_FINDINGS)
            if versions:result.update(status='observed',vulnerabilities=[findings[key] for key in sorted(findings)],
                                      withdrawn=sorted(withdrawn),advisory_receipt_indexes=sorted(indexes))
        except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):result['status']='unavailable'
        self.cache[key]=copy.deepcopy(result);return result

    def verify(self):self.tags.verify()

    def evidence(self):
        return {'profile':PROFILE,'observations':[copy.deepcopy(self.cache[key]) for key in sorted(self.cache)],
                'advisory_source':'github-global-advisories','advisory_types':list(ADVISORY_TYPES),
                'advisory_receipts':copy.deepcopy(self.action_api.receipts),
                'tag_bindings':[copy.deepcopy(self.tags.bindings[key]) for key in sorted(self.tags.bindings)],
                'tag_receipts':copy.deepcopy(self.tags.receipts),'tag_rechecks':copy.deepcopy(self.tags.rechecks)}
