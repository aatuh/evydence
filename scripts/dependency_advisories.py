#!/usr/bin/env python3
"""Exact-version OSV observations; unsupported or incomplete lookups stay unknown."""
import copy
from datetime import datetime,timezone
import hashlib
import json
import re
import time
import urllib.error
import urllib.request

import dependency_policy as policy

ENDPOINT='https://api.osv.dev/v1/query'
ECOSYSTEMS={'gomod':'Go','npm':'npm','pypi':'PyPI'}
MAX_REQUESTS=1024
MAX_RESPONSE_BYTES=4*1024*1024
MAX_TOTAL_BYTES=64*1024*1024
MAX_PAGES=8
MAX_FINDINGS=128
MAX_COMPONENTS=4096
SEVERITIES={'low':0,'moderate':1,'high':2,'critical':3,'unknown':4}
SEMVER=r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?'


class AdvisoryError(ValueError):
    def __init__(self):super().__init__('invalid or unavailable bounded exact-version advisory observation')


def require(value):
    if not value:raise AdvisoryError()


def identity(component):
    try:return dict(zip(('ecosystem','name','version'),policy._coordinates(component)))
    except (ValueError,TypeError,AttributeError):raise AdvisoryError() from None


def query(component):
    value=identity(component);ecosystem=value['ecosystem'];name=value['name'];version=value['version']
    if ecosystem not in ECOSYSTEMS:return None
    if ecosystem=='gomod':require('.' in name.split('/')[0] and re.fullmatch('v'+SEMVER,version))
    if ecosystem=='npm':
        require(re.fullmatch(r'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*',name)
                and re.fullmatch(SEMVER,version))
    if ecosystem=='pypi':
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*',name) and re.fullmatch(
            r'(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?'
            r'(?:\+[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?',version))
        name=re.sub(r'[-_.]+','-',name).lower()
    return {'package':{'ecosystem':ECOSYSTEMS[ecosystem],'name':name},'version':version}


def token(value):
    require(isinstance(value,str) and 0<len(value)<=4096 and all(32<ord(char)<127 for char in value))
    return value


def timestamp(value):
    require(isinstance(value,str) and 0<len(value)<=64)
    parsed=datetime.fromisoformat(value.replace('Z','+00:00'));require(parsed.tzinfo is not None)


def normalize(record,request):
    require(isinstance(record,dict));source_id=record.get('id')
    require(isinstance(source_id,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:._+-]{0,127}',source_id))
    timestamp(record.get('modified'))
    if 'withdrawn' in record:
        timestamp(record['withdrawn']);return source_id,None
    aliases=record.get('aliases',[])
    require(isinstance(aliases,list) and len(aliases)<=128 and all(isinstance(value,str) and len(value)<=128 for value in aliases))
    candidates={value for value in [source_id,*aliases] if policy.ADVISORY.fullmatch(value)}
    require(candidates)
    identifier=min(candidates,key=lambda value:(0 if value.startswith('GHSA-') else 1 if value.startswith('GO-') else 2,value))
    affected=record.get('affected');require(isinstance(affected,list) and 0<len(affected)<=512)
    matches=[];package=request['package']
    for row in affected:
        require(isinstance(row,dict));candidate=row.get('package',{})
        require(isinstance(candidate,dict))
        name=candidate.get('name');ecosystem=candidate.get('ecosystem')
        if ecosystem=='PyPI' and isinstance(name,str):name=re.sub(r'[-_.]+','-',name).lower()
        if ecosystem==package['ecosystem'] and name==package['name']:matches.append(row)
    require(matches)
    labels=[]
    for value in [record.get('database_specific',{}),
                  *(row.get(field,{}) for row in matches for field in ['database_specific','ecosystem_specific'])]:
        require(isinstance(value,dict))
        if 'severity' in value:
            severity=value['severity'];severity=severity.lower() if isinstance(severity,str) else 'unknown'
            labels.append('moderate' if severity=='medium' else severity if severity in SEVERITIES else 'unknown')
    severity=max(labels or ['unknown'],key=SEVERITIES.__getitem__)
    return source_id,{'id':identifier,'severity':severity}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_args):raise AdvisoryError()


class Client:
    def __init__(self):self.receipts=[];self.total_bytes=0;self.requests=0;self.cache={}

    def request(self,body):
        try:
            require(isinstance(body,dict) and set(body) in [{'package','version'},{'package','version','page_token'}])
            package=body['package'];require(isinstance(package,dict) and set(package)=={'name','ecosystem'})
            reverse={value:key for key,value in ECOSYSTEMS.items()}
            expected=query({'ecosystem':reverse[package['ecosystem']],'name':package['name'],'version':body['version']})
            require(expected=={key:body[key] for key in ['package','version']})
            if 'page_token' in body:token(body['page_token'])
            raw=json.dumps(body,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode();require(len(raw)<=8192)
            self.requests+=1;require(self.requests<=MAX_REQUESTS)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            request=urllib.request.Request(ENDPOINT,data=raw,method='POST',headers={
                'Accept':'application/json','Content-Type':'application/json','Accept-Encoding':'identity',
                'User-Agent':'evydence-dependency-advisories/1'})
            deadline=time.monotonic()+120
            with opener.open(request,timeout=20) as response:
                require(response.status==200 and response.geturl()==ENDPOINT
                        and response.headers.get('Content-Encoding','identity')=='identity')
                declared=response.headers.get('Content-Length')
                require(declared is None or re.fullmatch(r'[0-9]{1,12}',declared))
                require(declared is None or int(declared)<=MAX_RESPONSE_BYTES)
                contents=bytearray()
                while True:
                    require(time.monotonic()<=deadline)
                    chunk=response.read(min(65536,MAX_RESPONSE_BYTES-len(contents)+1))
                    if not chunk:break
                    contents.extend(chunk);self.total_bytes+=len(chunk)
                    require(len(contents)<=MAX_RESPONSE_BYTES and self.total_bytes<=MAX_TOTAL_BYTES)
                require(declared is None or len(contents)==int(declared))
            self.receipts.append({'endpoint':ENDPOINT,'method':'POST','request_sha256':hashlib.sha256(raw).hexdigest(),
                                  'response_sha256':hashlib.sha256(contents).hexdigest(),'response_bytes':len(contents)})
            document=policy.parse_document(bytes(contents));require(isinstance(document,dict));return document
        except urllib.error.HTTPError as error:
            error.close();raise AdvisoryError() from None
        except (OSError,ValueError,KeyError,TypeError,AttributeError,urllib.error.URLError):raise AdvisoryError() from None

    def observe(self,component):
        coordinates=identity(component);key=tuple(coordinates.values());request=query(coordinates)
        if key in self.cache:return copy.deepcopy(self.cache[key])
        require(len(self.cache)<MAX_COMPONENTS)
        result={'component':coordinates,'observed_at':datetime.now(timezone.utc).isoformat(),
                'status':'unsupported','vulnerabilities':None,'withdrawn':[],'receipt_indexes':[]}
        if request is not None:
            start=len(self.receipts)
            try:
                seen=set();tokens=set();findings={};withdrawn=[]
                for page in range(MAX_PAGES):
                    document=self.request(request)
                    require(set(document)<={'vulns','next_page_token'})
                    values=document.get('vulns',[]);require(isinstance(values,list) and len(values)<=MAX_FINDINGS)
                    for record in values:
                        source_id,value=normalize(record,request)
                        require(source_id not in seen);seen.add(source_id);require(len(seen)<=MAX_FINDINGS)
                        if value is None:withdrawn.append(source_id);continue
                        identifier=value['id'];previous=findings.get(identifier)
                        if previous is None or SEVERITIES[value['severity']]>SEVERITIES[previous['severity']]:findings[identifier]=value
                    next_token=document.get('next_page_token','')
                    require(isinstance(next_token,str))
                    if not next_token:break
                    token(next_token);require(next_token not in tokens and page+1<MAX_PAGES)
                    tokens.add(next_token);request={**request,'page_token':next_token}
                result.update(status='observed',vulnerabilities=[findings[key] for key in sorted(findings)],withdrawn=sorted(withdrawn))
            except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):result['status']='unavailable'
            result['receipt_indexes']=list(range(start,len(self.receipts)))
        self.cache[key]=copy.deepcopy(result);return result
