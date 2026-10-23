#!/usr/bin/env python3
"""Bind Go binary module checksums to bounded public source license bytes."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import zipfile
import zlib

import dependency_classifier as classifiers
import dependency_inventory as inventory
import dependency_tool_buildinfo as buildinfo

MAX_ZIP_BYTES=500*1024*1024
MAX_EXPANDED_BYTES=500*1024*1024
MAX_ENTRIES=65536
MAX_TOTAL_EXPANDED=2*1024*1024*1024
MAX_MODULES=512


class ToolSourceError(ValueError):
    def __init__(self):super().__init__('invalid or unavailable checksum-bound public Go tool source')


def require(value):
    if not value:raise ToolSourceError()


def observe_zip(root,path,name,version,expected_sum):
    """Go dirhash.Hash1: sorted filename/content hashes, excluding ZIP encoding.

    Matches Go's cmd/vendor/golang.org/x/mod/sumdb/dirhash/hash.go. Reject
    duplicate/unsafe entries rather than inheriting HashZip's duplicate behavior.
    No archive entry is extracted or executed.
    """
    try:
        inventory.checksum(expected_sum,'h1:',32)
        prefix=name+'@'+version+'/'
        with inventory.regular_stream(root,Path(path).relative_to(root)) as stream:
            require(os.fstat(stream.fileno()).st_size<=MAX_ZIP_BYTES)
            with zipfile.ZipFile(stream) as archive:
                rows=archive.infolist();require(0<len(rows)<=MAX_ENTRIES);seen=set();total=0
                for row in rows:
                    filename=row.filename;relative=filename[len(prefix):]
                    require(filename.startswith(prefix) and len(filename.encode())<=2048 and filename not in seen
                            and relative and all(part not in {'','.','..'} for part in relative.split('/'))
                            and '\\' not in filename and all(ord(c)>=32 and ord(c)!=127 for c in filename)
                            and stat.S_IFMT(row.external_attr>>16) in {0,stat.S_IFREG}
                            and not row.flag_bits&1 and 0<=row.file_size<=MAX_EXPANDED_BYTES)
                    seen.add(filename);total+=row.file_size;require(total<=MAX_EXPANDED_BYTES)
                digest=hashlib.sha256();files=[]
                for row in sorted(rows,key=lambda row:row.filename):
                    relative=row.filename[len(prefix):]
                    selected='/' not in relative and (inventory.LICENSE_NAME.fullmatch(relative) or inventory.NOTICE_NAME.fullmatch(relative))
                    if selected:require(row.file_size<=1024*1024 and len(files)<32)
                    content=bytearray();checksum=hashlib.sha256();count=0
                    with archive.open(row) as member:
                        while chunk:=member.read(65536):
                            count+=len(chunk);require(count<=row.file_size);checksum.update(chunk)
                            if selected:content.extend(chunk)
                    require(count==row.file_size)
                    digest.update((checksum.hexdigest()+'  '+row.filename+'\n').encode())
                    if selected:files.append({'file':relative,'kind':'notice' if inventory.NOTICE_NAME.fullmatch(relative) else 'license',
                                              'sha256':checksum.hexdigest(),'content':bytes(content)})
                actual='h1:'+base64.b64encode(digest.digest()).decode();require(actual==expected_sum)
        return {'sum':actual,'expanded_bytes':total,'files':files}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RuntimeError,EOFError,zipfile.BadZipFile,zlib.error):raise ToolSourceError() from None


class Sources:
    def __init__(self,work_root,parent,classifier):
        self.work=Path(tempfile.mkdtemp(prefix='dependency-tool-sources-',dir=work_root))
        self.environment=classifiers.environment(parent,self.work);self.environment['GOTELEMETRY']='off'
        self.classifier=classifier;self.cache={};self.total=0
        self.compiler_environment={**self.environment,'GOMODCACHE':str(self.work/'compiler-cache')}

    def resolve(self,name,version,expected_sum):
        """Read explicit module data only. Never resolve an upstream graph or run it."""
        try:
            selected=buildinfo.module({'Path':name,'Version':version,'Sum':expected_sum})
            require(selected['version']==version and selected['replacement'] is None)
            compiler=expected_sum is None
            if compiler:
                require(name=='golang.org/toolchain' and re.fullmatch(r'v0\.0\.1-go[1-9][0-9]*\.[0-9]+\.[0-9]+\.linux-amd64',version))
            else:inventory.checksum(expected_sum,'h1:',32)
            key=(name,version,expected_sum)
            if key in self.cache:return copy.deepcopy(self.cache[key])
            require(len(self.cache)<MAX_MODULES)
            work=Path(tempfile.mkdtemp(prefix='module-',dir=self.work))
            environment=self.compiler_environment if compiler else self.environment
            cache=Path(inventory._run(['go','env','GOMODCACHE'],work,environment,timeout=30).decode().strip())
            require(cache.is_absolute())
            rows=inventory.parse_go_stream(inventory._run(['go','mod','download','-json',name+'@'+version],work,environment))
            require(len(rows)==1);record=rows[0]
            require(record.get('Path')==name and record.get('Version')==version and record.get('Error') is None
                    and 'Replace' not in record)
            checksum=inventory.checksum(record.get('Sum'),'h1:',32)
            require(compiler or checksum==expected_sum)
            mod_sum=record.get('GoModSum')
            if mod_sum is not None:inventory.checksum(mod_sum,'h1:',32)
            private=work/'module.zip'
            with inventory.regular_stream(cache,Path(record['Zip']).relative_to(cache)) as source,private.open('xb') as target:
                private.chmod(0o600);size=0
                while chunk:=source.read(65536):
                    size+=len(chunk);require(size<=MAX_ZIP_BYTES);target.write(chunk)
            observation=observe_zip(work,private,name,version,checksum)
            self.total+=observation['expanded_bytes'];require(self.total<=MAX_TOTAL_EXPANDED)
            matches=self.classifier.classify(observation['files'])
            result=inventory.attach_licenses({'ecosystem':'gomod','name':name,'version':version,
                'source':{'sum':checksum,'go_mod_sum':mod_sum,'verification':'go-module-zip-h1',
                          'checksum_binding':'fresh-sumdb-toolchain' if compiler else 'binary-buildinfo'}},observation['files'],matches)
            self.cache[key]=result;return copy.deepcopy(result)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,UnicodeError,RecursionError):raise ToolSourceError() from None
