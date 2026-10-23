#!/usr/bin/env python3
"""Collect proposed dependency data using trusted Python and a base-built helper."""
import argparse
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile

import dependency_classifier as classifiers
import dependency_git_objects as objects
import dependency_inputs as inputs
import dependency_inventory as inventory
import dependency_reports as reports
import dependency_review_provider as provider
from release_lifecycle import read_bytes

ROOT=Path(__file__).resolve().parents[1]
SCHEMA='evydence-dependency-collection.v1'
DRIVER_FILES=('scripts/dependency_collection.py','scripts/dependency_classifier.py',
              'scripts/dependency_git_objects.py','scripts/dependency_inputs.py',
              'scripts/dependency_review_provider.py','scripts/dependency_reports.py')


class CollectionError(ValueError):
    def __init__(self):super().__init__('cannot collect verified Git dependency inputs with trusted tooling')


def require(value):
    if not value:raise CollectionError()


def verified_contents(observed,contents,source):
    require(isinstance(observed,dict) and observed.get('commit')==source
            and observed.get('missing_required')==[] and observed.get('unclassified_manifests')==[])
    rows=observed.get('files');provider.sha(observed.get('tree'))
    require(isinstance(rows,list) and 0<len(rows)<=inputs.MAX_INPUT_FILES and isinstance(contents,dict))
    names=set();total=0
    for row in rows:
        require(isinstance(row,dict));name=provider.git_path(row.get('path'))
        require(name not in names and row.get('mode') in {'100644','100755'});names.add(name)
        raw=contents[name]
        require(isinstance(raw,bytes) and len(raw)<=objects.MAX_BLOB_BYTES
                and type(row.get('bytes')) is int and len(raw)==row['bytes']
                and objects.object_id('blob',raw)==row.get('git_blob')
                and hashlib.sha256(raw).hexdigest()==row.get('sha256'))
        total+=len(raw);require(total<=objects.MAX_TOTAL_BLOB_BYTES)
    require(names==set(contents))


def verify_export(root,contents):
    actual=set();folders=0
    for directory,children,files in os.walk(root,followlinks=False):
        folders+=1;require(folders<=inputs.MAX_INPUT_FILES*64)
        require(len(children)+len(files)<=inputs.MAX_INPUT_FILES*64)
        for name in children:require(stat.S_ISDIR((Path(directory)/name).lstat().st_mode))
        for name in files:
            path=Path(directory)/name;mode=path.lstat().st_mode
            require(stat.S_ISREG(mode) and stat.S_IMODE(mode)==0o600)
            actual.add(path.relative_to(root).as_posix());require(len(actual)<=inputs.MAX_INPUT_FILES)
    require(actual==set(contents))
    require(all(read_bytes(root,name,objects.MAX_BLOB_BYTES)==raw for name,raw in contents.items()))


def collect(reader,trusted_base,source,work_root,parent_environment,*,classifier=None):
    """Run under the RAM gate; caller selects/authenticates the current target base."""
    try:
        trusted_base=provider.sha(trusted_base);source=provider.sha(source)
        work_root=Path(work_root).absolute();require(not work_root.is_symlink() and work_root.is_dir())
        code={name:read_bytes(ROOT,name,inventory.MAX_BYTES) for name in DRIVER_FILES}
        observed,contents=inputs.revision(reader,source);verified_contents(observed,contents,source)
        work=Path(tempfile.mkdtemp(prefix='dependency-collection-',dir=work_root))
        exported=work/'source';exported.mkdir(mode=0o700)
        for name,raw in contents.items():
            path=exported/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with path.open('xb') as target:target.write(raw)
            path.chmod(0o600)
        verify_export(exported,contents)
        if classifier is None:artifact=classifiers.build(reader,trusted_base,work,parent_environment)
        else:
            require(isinstance(classifier,classifiers.BuiltClassifier));classifier.verify();artifact=classifier
        require(artifact.receipt['trusted_base']==trusted_base)
        result=inventory.collect(exported,work,parent_environment,classifier=artifact)
        require(result['generator']['classifier']==artifact.receipt)
        artifact.verify();verify_export(exported,contents)
        require(all(read_bytes(ROOT,name,inventory.MAX_BYTES)==raw for name,raw in code.items()))
        return {'schema':SCHEMA,'observed_at':datetime.now(timezone.utc).isoformat(),
                'trusted_base':trusted_base,'source':observed,'source_bytes_verified':True,
                'trusted_driver_files':{name:hashlib.sha256(raw).hexdigest() for name,raw in code.items()},
                'inventory':result,'dependency_coverage_verified':False}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError):raise CollectionError() from None


class Parser(argparse.ArgumentParser):
    def error(self,_message):raise CollectionError()


def main(argv=None):
    parser=Parser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    selection=parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--local-repository',type=Path);selection.add_argument('--pull-request',type=int)
    parser.add_argument('--trusted-base',required=True);parser.add_argument('--source',required=True)
    parser.add_argument('--head-repository');parser.add_argument('--work-root',type=Path,required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--replace',action='store_true')
    handlers={}
    try:
        args=parser.parse_args(argv)
        def interrupted(_signum,_frame):raise CollectionError()
        for signum in (signal.SIGINT,signal.SIGTERM):handlers[signum]=signal.signal(signum,interrupted)
        directory,old=reports.directory(args.root,args.output,SCHEMA,args.replace);os.close(directory)
        if args.local_repository is not None:
            require(args.head_repository is None)
            report=collect(objects.LocalGit(args.local_repository),args.trusted_base,args.source,args.work_root,os.environ)
        else:
            require(args.head_repository is not None)
            api=provider.GitHub(source_inputs=True)
            snapshot=api.snapshot(args.pull_request,base=args.trusted_base,head=args.source,head_repository=args.head_repository)
            report=collect(objects.RemoteGit(api),snapshot['base'],snapshot['head'],args.work_root,os.environ)
            require(provider.pull_context(api.get('pulls/'+str(args.pull_request)),args.pull_request)=={
                key:snapshot[key] for key in ['pull_request','base','head','head_repository','changed_files']})
            report['provider_context']={key:snapshot[key] for key in [
                'repository','pull_request','base','head','comparison_base','head_repository']}
            report['receipts']=api.receipts
        reports.write(args.root,args.output,report,SCHEMA,replace=args.replace,expected=old)
        print('dependency-collection: trusted tooling and source bytes verified; full dependency admission remains separate')
        return 0
    except (OSError,ValueError,TypeError):
        print('dependency-collection: operation failed; inspect source identities and private work logs',file=sys.stderr)
        return 2
    finally:
        for signum,handler in handlers.items():signal.signal(signum,handler)


if __name__=='__main__':sys.exit(main())
