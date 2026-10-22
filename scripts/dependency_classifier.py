#!/usr/bin/env python3
"""Build a license classifier from explicitly trusted base Git objects only."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import signal
import sys
import tempfile

import dependency_git_objects as objects
import dependency_inventory as inventory
import dependency_policy as policy
import dependency_reports as reports
import dependency_review_provider as provider
from release_lifecycle import read_bytes
import support_matrix

ROOT=Path(__file__).resolve().parents[1]
SCHEMA='evydence-dependency-classifier.v1'
PACKAGE='tools/cmd/license-inventory/'
FIXED=('tools/go.mod','tools/go.sum','release/support-matrix.json')
MAX_FILES=64
MAX_SOURCE_BYTES=4*1024*1024
MAX_EXECUTABLE_BYTES=64*1024*1024
BUILD_ARGS=('go','build','-mod=readonly','-trimpath','-buildvcs=false','-o')


class ClassifierError(ValueError):
    def __init__(self): super().__init__('cannot verify trusted base license classifier')


def require(value):
    if not value: raise ClassifierError()


def sources(reader,trusted_base):
    """The caller must bind trusted_base to the current reviewed target base."""
    try:
        trusted_base=provider.sha(trusted_base)
        tree_id,tree=reader.tree(trusted_base); provider.sha(tree_id)
        selected=set(FIXED)
        for path in tree:
            if not path.startswith(PACKAGE): continue
            name=path[len(PACKAGE):]
            require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\.go',name) is not None)
            if not name.endswith('_test.go'): selected.add(path)
        require(PACKAGE+'main.go' in selected and len(selected)<=MAX_FILES)
        contents={}; records={}; total=0
        for path in sorted(selected):
            row=tree[path]
            require(row['type']=='blob' and row['mode'] in {'100644','100755'})
            identity=provider.sha(row['sha']); raw=reader.blob(identity)
            require(isinstance(raw,bytes) and len(raw)<=objects.MAX_BLOB_BYTES
                    and objects.object_id('blob',raw)==identity)
            total+=len(raw); require(total<=MAX_SOURCE_BYTES)
            contents[path]=raw
            records[path]={'git_blob':identity,'mode':row['mode'],'bytes':len(raw),
                           'sha256':hashlib.sha256(raw).hexdigest()}
        return contents,{'schema':SCHEMA,'trusted_base':trusted_base,'tree':tree_id,'sources':records}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,StopIteration): raise ClassifierError() from None


def environment(parent,workspace):
    # Only the operator's executable path and caches/certificates are reusable.
    # In particular, neither HOME/netrc nor Go/provider authentication survives.
    allowed=('PATH','GOCACHE','GOMODCACHE','SSL_CERT_FILE','SSL_CERT_DIR')
    result=inventory.tool_environment({key:parent[key] for key in allowed if parent.get(key)})
    home=workspace/'home'; home.mkdir(mode=0o700)
    temporary=workspace/'tmp'; temporary.mkdir(mode=0o700)
    result.update(HOME=str(home),TMPDIR=str(temporary),GOTMPDIR=str(temporary),
                  GOPATH=str(workspace/'gopath'),GOAUTH='off',GOVCS='*:off')
    return result


class BuiltClassifier:
    def __init__(self,workspace,receipt,environment):
        self.workspace=workspace; self.receipt=receipt; self.environment=environment
        self.executable=workspace/'license-classifier'

    def verify(self):
        raw=read_bytes(self.workspace,'license-classifier',MAX_EXECUTABLE_BYTES)
        require(raw and hashlib.sha256(raw).hexdigest()==self.receipt['binary_sha256'])

    def classify(self,files):
        """Execute only the built, digest-verified helper; license bytes are data."""
        try:
            self.verify()
            work=Path(tempfile.mkdtemp(prefix='scan-',dir=self.workspace))
            result=inventory._classify_files(files,self.executable,self.workspace,self.environment,work)
            self.verify()
            return result
        except (OSError,ValueError,TypeError,KeyError): raise ClassifierError() from None


def build(reader,trusted_base,work_root,parent_environment):
    """Must run under the host RAM gate; never called on a proposed source root."""
    try:
        contents,receipt=sources(reader,trusted_base)
        expected='go'+support_matrix.parse_policy(contents['release/support-matrix.json'])['go']['current']
        work_root=Path(work_root).absolute()
        require(not work_root.is_symlink() and work_root.is_dir())
        workspace=Path(tempfile.mkdtemp(prefix='dependency-classifier-',dir=work_root))
        for name,raw in contents.items():
            path=workspace/name; path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with path.open('xb') as target: target.write(raw)
            path.chmod(0o600)
        env=environment(parent_environment,workspace); folder=workspace/'tools'
        inventory._run(['go','telemetry','off'],folder,env,timeout=30)
        version=inventory._run(['go','version'],folder,env,timeout=30).decode('ascii').strip()
        require(re.fullmatch(r'go version '+re.escape(expected)+r' [a-z0-9]+/[a-z0-9]+',version) is not None)
        require(inventory._run(['go','env','GOTELEMETRY'],folder,env,timeout=30).strip()==b'off')
        manifest=policy.parse_document(inventory._run(['go','mod','edit','-json'],folder,env,
                                                     log=workspace/'manifest.log'))
        require(isinstance(manifest,dict) and manifest.get('Module',{}).get('Path')=='github.com/aatuh/evydence/tools'
                and not manifest.get('Replace') and not manifest.get('Exclude'))
        executable=workspace/'license-classifier'
        inventory._run([*BUILD_ARGS,str(executable),'./cmd/license-inventory'],folder,env,
                       log=workspace/'build.log')
        # _run requires exit status zero; Go versions need not use identical prose.
        inventory._run(['go','mod','verify'],folder,env,log=workspace/'verify.log')
        require(all(read_bytes(workspace,name,objects.MAX_BLOB_BYTES)==raw for name,raw in contents.items()))
        binary=read_bytes(workspace,'license-classifier',MAX_EXECUTABLE_BYTES); require(binary)
        receipt.update(go_version=expected,target=version.rsplit(' ',1)[1],
                       binary_sha256=hashlib.sha256(binary).hexdigest(),binary_bytes=len(binary),
                       build_arguments=[*BUILD_ARGS,'<private-output>','./cmd/license-inventory'],
                       module_verification='go-mod-verify',source_bytes_unchanged=True,telemetry='off')
        return BuiltClassifier(workspace,receipt,env)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError): raise ClassifierError() from None


class Parser(argparse.ArgumentParser):
    def error(self,_message): raise ClassifierError()


def main(argv=None):
    parser=Parser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--local-repository',type=Path)
    parser.add_argument('--trusted-base',required=True)
    parser.add_argument('--work-root',type=Path,required=True)
    parser.add_argument('--output',required=True); parser.add_argument('--replace',action='store_true')
    handlers={}
    try:
        args=parser.parse_args(argv)
        def interrupted(_signum,_frame): raise ClassifierError()
        for signum in (signal.SIGINT,signal.SIGTERM): handlers[signum]=signal.signal(signum,interrupted)
        directory,old=reports.directory(args.root,args.output,SCHEMA,args.replace); os.close(directory)
        result=build(objects.LocalGit(args.local_repository or args.root),args.trusted_base,args.work_root,os.environ)
        reports.write(args.root,args.output,result.receipt,SCHEMA,replace=args.replace,expected=old)
        print('dependency-classifier: trusted base build verified; dependency admission remains separate')
        return 0
    except (OSError,ValueError,TypeError):
        print('dependency-classifier: build failed; inspect trusted source identities and private work logs',file=sys.stderr)
        return 2
    finally:
        for signum,handler in handlers.items(): signal.signal(signum,handler)


if __name__=='__main__': sys.exit(main())
