#!/usr/bin/env python3
"""Bounded immutable Git bytes for trusted tooling; never execute source code."""
import base64
import hashlib
import os
from pathlib import Path
import re

import dependency_inventory as inventory
import dependency_review_provider as provider

MAX_BLOB_BYTES = 1024 * 1024
MAX_TOTAL_BLOB_BYTES = 32 * 1024 * 1024
MAX_GIT_COMMANDS = 1024


class ObjectError(ValueError):
    def __init__(self): super().__init__('invalid or unavailable bounded immutable Git input')


def require(value):
    if not value: raise ObjectError()


def object_id(kind,raw):
    require(kind in {'blob','commit'} and isinstance(raw,bytes) and len(raw)<=MAX_BLOB_BYTES)
    return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw,usedforsecurity=False).hexdigest()


def decode_blob(value,expected):
    try:
        expected=provider.sha(expected)
        require(isinstance(value,dict) and value.get('sha')==expected and value.get('encoding')=='base64'
                and type(value.get('size')) is int and 0<=value['size']<=MAX_BLOB_BYTES)
        content=value.get('content')
        require(isinstance(content,str) and len(content)<=((MAX_BLOB_BYTES+2)//3)*4+MAX_BLOB_BYTES//32+8
                and re.fullmatch(r'[A-Za-z0-9+/=\n]*',content))
        compact=content.replace('\n',''); raw=base64.b64decode(compact,validate=True)
        require(len(raw)==value['size'] and len(raw)<=MAX_BLOB_BYTES
                and base64.b64encode(raw).decode()==compact and object_id('blob',raw)==expected)
        return raw
    except (OSError,ValueError,TypeError,KeyError,AttributeError): raise ObjectError() from None


class Cache:
    def __init__(self): self.blobs={}; self.blob_bytes=0; self.trees={}
    def remember(self,identity,raw):
        require(object_id('blob',raw)==identity)
        self.blob_bytes+=len(raw); require(self.blob_bytes<=MAX_TOTAL_BLOB_BYTES)
        self.blobs[identity]=raw; return raw


class RemoteGit(Cache):
    kind='github'
    def __init__(self,api):
        super().__init__(); require(api.source_inputs is True); self.api=api
    def blob(self,identity):
        try:
            identity=provider.sha(identity)
            if identity not in self.blobs:
                self.remember(identity,decode_blob(self.api.get('git/blobs/'+identity),identity))
            return self.blobs[identity]
        except (OSError,ValueError,TypeError,KeyError,AttributeError): raise ObjectError() from None
    def tree(self,commit):
        try:
            commit=provider.sha(commit)
            if commit not in self.trees:
                record=self.api.get('git/commits/'+commit); require(record.get('sha')==commit)
                identity=provider.sha(record['tree']['sha'])
                leaves=provider.git_tree(self.api.get('git/trees/'+identity+'?recursive=1'),identity)
                self.trees[commit]=(identity,leaves)
            identity,leaves=self.trees[commit]
            return identity,{path:dict(row) for path,row in leaves.items()}
        except (OSError,ValueError,TypeError,KeyError,AttributeError): raise ObjectError() from None


class LocalGit(Cache):
    kind='local-git'
    def __init__(self,root):
        super().__init__(); self.root=Path(root).absolute(); self.count=0
        require(not self.root.is_symlink() and self.root.is_dir())
        actual=self.run(['rev-parse','--show-toplevel']).decode('utf-8').strip()
        require(Path(actual).resolve()==self.root.resolve())
    def run(self,args):
        try:
            allowed=args in (['rev-parse','--show-toplevel'],['rev-parse','--verify','HEAD^{commit}'])
            if isinstance(args,list) and len(args)==3 and args[0]=='cat-file' and args[1] in {'-s','blob','commit'}:
                provider.sha(args[2]); allowed=True
            if isinstance(args,list) and len(args)==5 and args[:4]==['ls-tree','-r','-t','-z']:
                provider.sha(args[4]); allowed=True
            require(allowed); self.count+=1; require(self.count<=MAX_GIT_COMMANDS)
            environment={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LC_ALL':'C.UTF-8',
                'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_NO_REPLACE_OBJECTS':'1',
                'GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0','GIT_NO_LAZY_FETCH':'1'}
            return inventory._run(['git','--no-lazy-fetch','-c','core.fsmonitor=false','-c','core.hooksPath='+os.devnull,
                '-c','maintenance.auto=false','-c','gc.auto=0',*args],self.root,environment,timeout=30)
        except (OSError,ValueError,TypeError,KeyError,AttributeError): raise ObjectError() from None
    def head(self): return provider.sha(self.run(['rev-parse','--verify','HEAD^{commit}']).decode('ascii').strip())
    def read_object(self,identity,kind):
        identity=provider.sha(identity)
        size=self.run(['cat-file','-s',identity]).strip()
        require(re.fullmatch(rb'[0-9]{1,10}',size) and int(size)<=MAX_BLOB_BYTES)
        raw=self.run(['cat-file',kind,identity])
        require(len(raw)==int(size) and object_id(kind,raw)==identity)
        return raw
    def blob(self,identity):
        try:
            identity=provider.sha(identity)
            if identity not in self.blobs: self.remember(identity,self.read_object(identity,'blob'))
            return self.blobs[identity]
        except (OSError,ValueError,TypeError,KeyError,AttributeError): raise ObjectError() from None
    def tree(self,commit):
        try:
            commit=provider.sha(commit)
            if commit not in self.trees:
                raw=self.read_object(commit,'commit'); first=raw.split(b'\n',1)[0]
                require(re.fullmatch(rb'tree [0-9a-f]{40}',first))
                identity=first[5:].decode('ascii'); data=self.run(['ls-tree','-r','-t','-z',identity])
                rows=[]
                for record in data.split(b'\0')[:-1]:
                    metadata,path=record.split(b'\t',1); mode,kind,blob=metadata.decode('ascii').split(' ')
                    rows.append({'path':path.decode('utf-8'),'mode':mode,'type':kind,'sha':blob})
                require(not data or data.endswith(b'\0'))
                leaves=provider.git_tree({'sha':identity,'truncated':False,'tree':rows},identity)
                self.trees[commit]=(identity,leaves)
            identity,leaves=self.trees[commit]
            return identity,{path:dict(row) for path,row in leaves.items()}
        except (OSError,ValueError,TypeError,KeyError,AttributeError): raise ObjectError() from None
