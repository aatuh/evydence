#!/usr/bin/env python3
"""Bind declared dependency inputs to Git bytes; admission remains a separate step."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import sys

import dependency_actions as actions
import dependency_git_objects as objects
import dependency_go_tools as go_tools
import dependency_inventory as inventory
import dependency_policy as policy
import dependency_reports as reports
import dependency_review_provider as provider
import fixture_provenance as fixtures
import python_qa

ROOT=Path(__file__).resolve().parents[1]
SCHEMA='evydence-dependency-inputs.v1'
MAX_INPUT_FILES=256
GROUPS={
    'go-application':('go.mod','go.sum'),
    'go-qa':('tools/go.mod','tools/go.sum'),
    'go-scanner':('release/tools/syft.go.mod','release/tools/syft.go.sum'),
    'node-marketing':('site/marketing/package.json','site/marketing/package-lock.json'),
    'python-qa':('tools/requirements-qa.txt',),
    'tools':('release/support-matrix.json',go_tools.CATALOG,'Makefile',go_tools.WORKFLOW),
    'actions':(),
    'images':('Dockerfile','deploy/local-dependencies/Dockerfile','docker-compose.yml',
              'compose.production-like.yml','deploy/airgap/manifest.yaml','deploy/helm/evydence/values.yaml'),
    'fixtures':(fixtures.CATALOG,fixtures.CORPUS,'LICENSE'),
    'policy':('.github/dependabot.yml',),
    'tooling':(),
}
MANIFEST_NAMES={'go.mod','go.sum','go.work','go.work.sum','package.json','package-lock.json','npm-shrinkwrap.json',
    'yarn.lock','pnpm-lock.yaml','pyproject.toml','poetry.lock','uv.lock','Pipfile','Pipfile.lock','setup.py','setup.cfg',
    'Cargo.toml','Cargo.lock','pom.xml','build.gradle','build.gradle.kts','Gemfile','Gemfile.lock','composer.json',
    'composer.lock','.gitmodules','action.yml','action.yaml','packages.lock.json'}


class InputError(ValueError):
    def __init__(self): super().__init__('invalid or incomplete immutable dependency input coverage')


def require(value):
    if not value: raise InputError()


def fixture_payload(path):
    name=PurePosixPath(path)
    for root in fixtures.ROOTS:
        if not path.startswith(root+'/'): continue
        if (path in {fixtures.CATALOG,fixtures.CORPUS} or path.startswith('testdata/licenses/') or name.suffix=='.md'
            or root=='internal/app/parsers' and '/testdata/' not in path and '/schema/' not in path): continue
        return True
    return False


def descriptor(path):
    name=PurePosixPath(path).name
    return (name in MANIFEST_NAMES or name.lower().startswith('dockerfile')
            or name.startswith('requirements') and name.endswith('.txt')
            or name.endswith(('.mod','.sum','.csproj','.fsproj','.lock'))
            or any(part in {'vendor','node_modules','third_party','third-party'} for part in path.split('/')))


def catalog(tree):
    try:
        require(isinstance(tree,dict) and len(tree)<=provider.MAX_TREE_ENTRIES)
        paths={}; missing=[]
        def add(path,role): paths.setdefault(path,set()).add(role)
        for path,row in tree.items():
            provider.git_path(path)
            require(isinstance(row,dict) and row.get('mode') in provider.MODES
                    and provider.MODES[row['mode']]==row.get('type') and row['type'] in {'blob','commit'})
            provider.sha(row.get('sha'))
        for role,names in GROUPS.items():
            for path in names:
                if path in tree: add(path,role)
                else: missing.append(role+':'+path)
        actual_workflows=[]
        for path in tree:
            name=PurePosixPath(path); parent=name.parent.as_posix()
            if parent in actions.WORKFLOW_ROOTS and name.suffix in {'.yml','.yaml'}:
                add(path,'actions')
                if parent=='.github/workflows': actual_workflows.append(path)
            if name.name in {'action.yml','action.yaml'} and path.startswith(('.github/actions/','docs/github-actions/')):
                add(path,'actions')
            if path.startswith('deploy/helm/evydence/') and (name.suffix in {'.yaml','.yml','.tpl'} or name.name=='.helmignore'):
                add(path,'images')
            if fixture_payload(path) or path.startswith('testdata/licenses/') or (
                name.name in {'SOURCE.md','SOURCES.md'} and any(path.startswith(root+'/') for root in fixtures.ROOTS)):
                add(path,'fixtures')
            if path in inventory.GENERATOR_FILES or path.startswith('scripts/dependency') and name.suffix=='.py': add(path,'tooling')
            if name.suffix=='.sh' and not fixture_payload(path): add(path,'tooling')
            if path=='.dockerignore': add(path,'images')
            if path in {'release/dependency-policy.json','release/dependency-exceptions.json'}: add(path,'policy')
        if not actual_workflows: missing.append('actions:.github/workflows')
        require(len(paths)<=MAX_INPUT_FILES)
        for path in paths: require(tree[path]['type']=='blob' and tree[path]['mode'] in {'100644','100755'})
        unknown=sorted(path for path in tree if path not in paths and (descriptor(path) or tree[path]['type']=='commit'))
        return {'paths':{path:sorted(roles) for path,roles in sorted(paths.items())},
                'missing_required':sorted(missing),'unclassified_manifests':unknown}
    except (OSError,ValueError,TypeError,KeyError,AttributeError): raise InputError() from None


def fixture_hashes(contents,tree):
    if fixtures.CATALOG not in contents: return False
    data=policy.parse_document(contents[fixtures.CATALOG])
    require(isinstance(data,dict) and set(data)=={'schema','fixtures','notices'} and data['schema']==fixtures.SCHEMA
            and isinstance(data['fixtures'],list) and 0<len(data['fixtures'])<=512
            and isinstance(data['notices'],list) and 0<len(data['notices'])<=64)
    expected={path for path in tree if fixture_payload(path)}; covered=set()
    def check(row,notice=False):
        require(isinstance(row,dict))
        path=fixtures.notice_path(row['path']) if notice else fixtures.path_value(row['path'])
        require(path in contents and isinstance(row.get('sha256'),str) and re.fullmatch(r'[0-9a-f]{64}',row['sha256'])
                and hashlib.sha256(contents[path]).hexdigest()==row['sha256'])
        return path
    for row in data['notices']: check(row,True)
    for row in data['fixtures']:
        require(isinstance(row,dict) and isinstance(row.get('files'),list) and 0<len(row['files'])<=64)
        for file in row['files']:
            path=check(file); require(path in expected and path not in covered); covered.add(path)
    require(covered==expected)
    return True


def revision(reader,commit):
    try:
        commit=provider.sha(commit); tree_id,tree=reader.tree(commit); provider.sha(tree_id)
        selected=catalog(tree); contents={}; records=[]; total=0
        for path,roles in selected['paths'].items():
            entry=tree[path]; raw=reader.blob(entry['sha'])
            require(isinstance(raw,bytes) and len(raw)<=objects.MAX_BLOB_BYTES and objects.object_id('blob',raw)==entry['sha'])
            total+=len(raw); require(total<=objects.MAX_TOTAL_BLOB_BYTES)
            contents[path]=raw
            records.append({'path':path,'roles':roles,'mode':entry['mode'],'git_blob':entry['sha'],
                            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        schemas=[]
        if fixture_hashes(contents,tree): schemas.append('fixture-file-coverage-and-hashes')
        if all(path in contents for path in GROUPS['node-marketing']):
            inventory.node_components(*(policy.parse_document(contents[path]) for path in GROUPS['node-marketing']))
            schemas.append('npm-lock')
        if GROUPS['python-qa'][0] in contents:
            python_qa.parse_requirements(contents[GROUPS['python-qa'][0]]); schemas.append('python-qa-pins')
        if all(path in contents for path in go_tools.INPUTS):
            go_tools.profiles(contents); schemas.append('standalone-go-installation-bindings')
        return {'commit':commit,'tree':tree_id,'files':records,'missing_required':selected['missing_required'],
                'unclassified_manifests':selected['unclassified_manifests'],'schemas_verified':sorted(schemas)},contents
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError): raise InputError() from None


def collect(reader,base,head):
    try:
        before,_=revision(reader,base); after,_=revision(reader,head)
        old={row['path']:row for row in before['files']}; new={row['path']:row for row in after['files']}
        changes=[{'path':path,'before':old.get(path),'after':new.get(path)} for path in sorted(set(old)|set(new)) if old.get(path)!=new.get(path)]
        return {'schema':SCHEMA,'observed_at':datetime.now(timezone.utc).isoformat(),'reader':reader.kind,
                'base':before,'head':after,'changes':changes,'selected_input_bytes_verified':True,
                'source_catalog_covered':not after['missing_required'] and not after['unclassified_manifests'],
                'dependency_coverage_verified':False}
    except (OSError,ValueError,TypeError,KeyError,AttributeError): raise InputError() from None


def require_coverage(report):
    require(isinstance(report,dict) and report.get('schema')==SCHEMA and report.get('selected_input_bytes_verified') is True
            and report.get('source_catalog_covered') is True and report.get('head',{}).get('missing_required')==[]
            and report['head'].get('unclassified_manifests')==[])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT,help='Output root; source code is never read from the working tree.')
    parser.add_argument('--local-repository',type=Path); parser.add_argument('--base'); parser.add_argument('--head')
    parser.add_argument('--pull-request',type=int); parser.add_argument('--head-repository')
    parser.add_argument('--output'); parser.add_argument('--replace',action='store_true')
    parser.add_argument('--check-local',action='store_true',help='Check the committed HEAD source catalog without writing a report.')
    args=parser.parse_args(argv); handlers={}
    try:
        def interrupted(_signum,_frame): raise InputError()
        for signum in (signal.SIGINT,signal.SIGTERM): handlers[signum]=signal.signal(signum,interrupted)
        if args.check_local:
            require(all(value is None for value in [args.base,args.head,args.pull_request,args.head_repository,args.output]))
            reader=objects.LocalGit(args.local_repository or args.root); commit=reader.head(); report=collect(reader,commit,commit)
            require_coverage(report)
            print('dependency-inputs: committed HEAD source bytes and declared catalog verified; dependency admission remains separate')
            return 0
        require(args.output is not None and args.base is not None and args.head is not None)
        directory,old=reports.directory(args.root,args.output,SCHEMA,args.replace); os.close(directory)
        if args.local_repository is not None:
            require(args.pull_request is None and args.head_repository is None)
            report=collect(objects.LocalGit(args.local_repository),args.base,args.head)
        else:
            require(args.pull_request is not None and args.head_repository is not None)
            api=provider.GitHub(source_inputs=True)
            snapshot=api.snapshot(args.pull_request,base=args.base,head=args.head,head_repository=args.head_repository)
            report=collect(objects.RemoteGit(api),snapshot['comparison_base'],snapshot['head'])
            require(provider.pull_context(api.get('pulls/'+str(args.pull_request)),args.pull_request)=={
                key:snapshot[key] for key in ['pull_request','base','head','head_repository','changed_files']})
            report['provider_context']={key:snapshot[key] for key in ['repository','pull_request','base','head','comparison_base','head_repository']}
            report['receipts']=api.receipts
        reports.write(args.root,args.output,report,SCHEMA,replace=args.replace,expected=old)
        print('dependency-inputs: source observation written; complete dependency admission remains unverified')
        return 0 if report['source_catalog_covered'] else 1
    except (OSError,ValueError,TypeError):
        print('dependency-inputs: operation failed; inspect immutable source identities and coverage',file=sys.stderr); return 2
    finally:
        for signum,handler in handlers.items(): signal.signal(signum,handler)


if __name__=='__main__': sys.exit(main())
