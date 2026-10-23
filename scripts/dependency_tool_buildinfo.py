#!/usr/bin/env python3
"""Inspect checksum-verified Go tool binaries as data without target execution."""
import gzip
import hashlib
import io
from pathlib import Path
import re
import stat
import tarfile

import dependency_advisories as advisories
import dependency_build_tools as tools
import dependency_classifier as classifiers
import dependency_inventory as inventory
import dependency_policy as policy

MAX_MODULES=4096
MAX_SETTINGS=256


class BuildInfoError(ValueError):
    def __init__(self):super().__init__('invalid or unbound build-tool archive or Go metadata')


def require(value):
    if not value:raise BuildInfoError()


def module(value,*,replacement=False):
    require(isinstance(value,dict) and set(value)<={'Path','Version','Sum','Replace'})
    name=value.get('Path');version=value.get('Version','')
    require(isinstance(name,str) and isinstance(version,str))
    if replacement and not version:
        require(0<len(name)<=1024 and '\0' not in name and not value.get('Replace'))
        return {'kind':'local','name':None,'version':None,'version_state':'unknown','sum':None,'replacement':None}
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._~+!/-]{0,255}',name)
            and '.' in name.split('/')[0] and all(part not in {'','.','..'} for part in name.split('/')))
    known=re.fullmatch('v'+advisories.SEMVER,version) is not None
    checksum=value.get('Sum')
    if checksum=='':checksum=None
    if checksum is not None:inventory.checksum(checksum,'h1:',32)
    replaced=value.get('Replace')
    if replacement:require(replaced is None)
    return {'kind':'module','name':name,'version':version if known else None,
            'version_state':'release' if known else 'development' if version=='(devel)' else 'unknown',
            'sum':checksum,'replacement':None if replaced is None else module(replaced,replacement=True)}


def project(raw):
    try:
        data=policy.parse_document(raw)
        require(isinstance(data,dict) and set(data)<={'GoVersion','Path','Main','Deps','Settings'})
        main=module(data['Main']);rows=data.get('Deps',[]);settings=data.get('Settings',[])
        require(isinstance(rows,list) and len(rows)<=MAX_MODULES and isinstance(settings,list) and len(settings)<=MAX_SETTINGS)
        names={main['name']};modules=[]
        for row in rows:
            value=module(row);require(value['name'] not in names);names.add(value['name']);modules.append(value)
        selected={}
        for setting in settings:
            require(isinstance(setting,dict) and set(setting)=={'Key','Value'}
                    and isinstance(setting['Key'],str) and isinstance(setting['Value'],str))
            key=setting['Key']
            if key not in {'GOOS','GOARCH','CGO_ENABLED'}:continue
            require(key not in selected and len(setting['Value'])<=64);selected[key]=setting['Value']
        cgo=selected.get('CGO_ENABLED');require(cgo in {None,'0','1'})
        compiler=data.get('GoVersion');known=isinstance(compiler,str) and re.fullmatch(r'go[1-9][0-9]*\.[0-9]+\.[0-9]+',compiler)
        return {'go_version':compiler if known else None,'main':main,'modules':sorted(modules,key=lambda value:value['name']),
                'platform':{'goos':selected.get('GOOS'),'goarch':selected.get('GOARCH'),
                            'cgo_enabled':None if cgo is None else cgo=='1'}}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise BuildInfoError() from None


def file_digest(root,name):
    result=hashlib.sha256()
    with inventory.regular_stream(root,name) as stream:
        while chunk:=stream.read(65536):result.update(chunk)
    return result.hexdigest()


def inspect(raw,row,work,parent,expected_go):
    """Caller runs under RAM gate. Only the qualified Go reader is executed."""
    try:
        observation,_files=tools.observe(raw,row)
        require(isinstance(expected_go,str) and re.fullmatch(r'go[1-9][0-9]*\.[0-9]+\.[0-9]+',expected_go))
        work=Path(work).absolute();require(not work.is_symlink() and work.is_dir() and stat.S_IMODE(work.stat().st_mode)==0o700)
        binary=work/'artifact-go-binary';target=('linux-amd64/' if row['name']=='helm' else '')+row['name'];found=False
        with gzip.GzipFile(fileobj=io.BytesIO(raw),mode='rb') as compressed:
            expanded=tools._Expanded(compressed)
            with tarfile.open(fileobj=expanded,mode='r|') as archive:
                for member in archive:
                    name='/'.join(part for part in member.name.split('/') if part!='.')
                    if name!=target:continue
                    require(not found and member.isreg() and not member.issparse())
                    source=archive.extractfile(member);require(source is not None)
                    with source,binary.open('xb') as output:
                        binary.chmod(0o600);count=0
                        while chunk:=source.read(65536):
                            count+=len(chunk);require(count<=member.size and count<=tools.MAX_EXPANDED_BYTES);output.write(chunk)
                        require(count==member.size)
                    found=True
        require(found and file_digest(work,binary.name)==observation['binary_sha256'])
        environment=classifiers.environment(parent,work);environment['GOTELEMETRY']='off'
        reader=inventory._run(['go','version'],work,environment,timeout=30).decode('ascii').strip()
        require(reader=='go version '+expected_go+' linux/amd64')
        metadata=inventory._run(['go','version','-m','-json',str(binary)],work,environment,timeout=120)
        result=project(metadata)
        require(file_digest(work,binary.name)==observation['binary_sha256'])
        return {'archive_sha256':row['source']['sha256'],'binary_sha256':observation['binary_sha256'],
                'reader_go_version':expected_go,'buildinfo_sha256':hashlib.sha256(metadata).hexdigest(),'buildinfo':result}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,EOFError,tarfile.TarError):raise BuildInfoError() from None
