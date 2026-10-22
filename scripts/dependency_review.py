#!/usr/bin/env python3
"""Run trusted PR dependency collection and decisions without passing coverage gaps."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

import dependency_admission as admission
import dependency_advisories as advisories
import dependency_action_advisories as action_advisories
import dependency_classifier as classifiers
import dependency_collection as collection
import dependency_exception_reviews as exception_reviews
import dependency_git_objects as objects
import dependency_inputs as inputs
import dependency_image_admission as image_admission
import dependency_images as images
import dependency_inventory as inventory
import dependency_policy as policy
import dependency_reports as reports
import dependency_review_join as join
import dependency_review_provider as provider
import dependency_tool_admission as tool_admission
from release_lifecycle import read_bytes

ROOT=Path(__file__).resolve().parents[1]
SCHEMA='evydence-dependency-review.v1'
DRIVER_FILES=('scripts/dependency_review.py','scripts/dependency_review_join.py','scripts/dependency_admission.py',
              'scripts/dependency_exception_reviews.py','scripts/dependency_advisories.py',
              'scripts/dependency_fixture_advisories.py','scripts/dependency_image_admission.py',
              'scripts/dependency_image_packages.py','scripts/dependency_action_advisories.py',
              'scripts/dependency_tool_admission.py','scripts/dependency_tool_buildinfo.py',
              'scripts/dependency_tool_sources.py')+tuple(sorted({
                  name for name in (*inventory.GENERATOR_FILES,*images.GENERATOR_FILES) if name.endswith('.py')}))


class ReviewError(ValueError):
    def __init__(self):super().__init__('invalid or incomplete trusted dependency review context')


def require(value):
    if not value:raise ReviewError()


def digest(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    require(len(raw)<=8*1024*1024);return hashlib.sha256(raw).hexdigest()


def run(api,pull_number,base,head,head_repository,work_root,parent_environment,*,today=None,syft=None):
    try:
        work_root=Path(work_root).absolute();require(not work_root.is_symlink() and work_root.is_dir())
        base=provider.sha(base);head=provider.sha(head);pull_number=provider.number(pull_number)
        head_repository=provider.actions.repository(head_repository)
        live_clock=today is None;today=datetime.now(timezone.utc).date() if live_clock else today
        code={name:read_bytes(ROOT,name,policy.MAX_DOCUMENT_BYTES) for name in DRIVER_FILES}
        snapshot=api.snapshot(pull_number,base=base,head=head,head_repository=head_repository)
        require(snapshot.get('schema')==provider.SCHEMA and snapshot.get('repository')==provider.REPOSITORY
                and snapshot.get('provider_authenticated') is True and snapshot.get('file_listing_verified') is True
                and snapshot.get('base')==base and snapshot.get('head')==head
                and snapshot.get('head_repository')==head_repository and snapshot.get('comparison_base')==base)
        reader=objects.RemoteGit(api)
        rules,_selected=admission.load_policy(reader,base,today)
        proposed_rules,proposed_policy=admission.load_policy(reader,head,today)
        require(not proposed_policy.get('expired_exceptions'))
        proposed_reviews=exception_reviews.verify(proposed_rules,api,today)
        for source in (base,head):
            observed,contents=inputs.revision(reader,source);collection.verified_contents(observed,contents,source)
        artifact=classifiers.build(reader,base,work_root,parent_environment)
        require(artifact.receipt['trusted_base']==base)
        before=collection.collect(reader,base,base,work_root,parent_environment,classifier=artifact)
        after=collection.collect(reader,base,head,work_root,parent_environment,classifier=artifact)
        action_api=action_advisories.Client(advisories.Client(),after,base,head)
        advisory_api=tool_admission.Client(action_api,after,base,head,work_root,parent_environment,artifact,reader,today,review_api=api)
        decision=join.assess(reader,base,base,head,before,after,snapshot,advisory_api,today,review_api=api)
        image_decision=image_admission.assess(reader,base,head,before,after,work_root,advisory_api,today,syft=syft,review_api=api)
        tool_decision=advisory_api.evidence()
        gaps=set()
        for value in [before,after]:
            remaining=value['inventory'].get('remaining_scopes');require(isinstance(remaining,list)
                and all(isinstance(scope,str) and scope in {'images','action-local-references'} for scope in remaining))
            gaps.update('source:'+scope for scope in remaining if scope!='images' or image_decision.get('image_coverage_verified') is not True)
        gaps.update('images:'+scope for scope in image_decision['coverage_gaps'])
        if tool_decision.get('tool_coverage_verified') is not True:gaps.add('build-tool-profile')
        if decision.get('dependency_coverage_verified') is not True:gaps.add('complete-admission-profile')
        require(provider.pull_context(api.get('pulls/'+str(pull_number)),pull_number)=={
            key:snapshot[key] for key in ['pull_request','base','head','head_repository','changed_files']})
        combined_reviews={}
        for proof in [*decision.get('exception_reviews',[]),*image_decision.get('exception_reviews',[]),
                      *tool_decision.get('exception_reviews',[])]:
            identifier=proof['exception_id'];require(identifier not in combined_reviews or combined_reviews[identifier]==proof)
            combined_reviews[identifier]=proof
        used=set(combined_reviews)
        applicable={**rules,'exceptions':[row for row in rules['exceptions'] if row['id'] in used]}
        final_reviews=exception_reviews.verify(applicable,api,today)
        require({proof['exception_id']:proof for proof in final_reviews}==combined_reviews)
        require(exception_reviews.verify(proposed_rules,api,today)==proposed_reviews)
        advisory_api.verify()
        action_api.verify()
        artifact.verify()
        require(all(read_bytes(ROOT,name,policy.MAX_DOCUMENT_BYTES)==raw for name,raw in code.items()))
        finished=datetime.now(timezone.utc)
        require(not live_clock or finished.date()==today)
        covered=not gaps and decision.get('dependency_coverage_verified') is True and image_decision.get('image_coverage_verified') is True \
            and tool_decision.get('tool_coverage_verified') is True
        return {'schema':SCHEMA,'observed_at':finished.isoformat(),
                'provider_context':{key:snapshot[key] for key in ['repository','pull_request','base','head','head_repository','comparison_base']},
                'source_base':before['source'],'source_head':after['source'],
                'semantic_collection_sha256':{'base':digest(before),'head':digest(after)},
                'trusted_driver_files':{name:hashlib.sha256(raw).hexdigest() for name,raw in code.items()},
                'decision':decision,'image_decision':image_decision,'tool_decision':tool_decision,'exception_reviews':final_reviews,
                'action_advisories':action_api.evidence(),'advisory_receipts':advisory_api.receipts,
                'coverage_gaps':sorted(gaps),'dependency_coverage_verified':covered,
                'proposed_policy':proposed_policy,'proposed_policy_reviews':proposed_reviews,
                'passed':covered and decision.get('package_decision_passed') is True
                    and image_decision.get('image_decision_passed') is True
                    and tool_decision.get('tool_decision_passed') is True,'receipts':api.receipts}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ReviewError() from None


class Parser(argparse.ArgumentParser):
    def error(self,_message):raise ReviewError()


def main(argv=None):
    parser=Parser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--pull-request',type=int,required=True)
    parser.add_argument('--base',required=True);parser.add_argument('--head',required=True)
    parser.add_argument('--head-repository',required=True);parser.add_argument('--work-root',type=Path,required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--replace',action='store_true')
    parser.add_argument('--syft',type=Path,help='operator-selected qualified scanner; required for changed registry images')
    handlers={}
    try:
        args=parser.parse_args(argv)
        def interrupted(_signum,_frame):raise ReviewError()
        for signum in (signal.SIGINT,signal.SIGTERM):handlers[signum]=signal.signal(signum,interrupted)
        directory,old=reports.directory(args.root,args.output,SCHEMA,args.replace);os.close(directory)
        report=run(provider.GitHub(source_inputs=True),args.pull_request,args.base,args.head,args.head_repository,args.work_root,os.environ,syft=args.syft)
        reports.write(args.root,args.output,report,SCHEMA,replace=args.replace,expected=old)
        print('dependency-review: full admission passed' if report['passed'] else 'dependency-review: blocked or incomplete; inspect the review report')
        return 0 if report['passed'] else 1
    except (OSError,ValueError,TypeError):
        print('dependency-review: failed to verify current PR sources, policy or provider data',file=sys.stderr);return 2
    finally:
        for signum,handler in handlers.items():signal.signal(signum,handler)


if __name__=='__main__':sys.exit(main())
