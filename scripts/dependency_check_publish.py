#!/usr/bin/env python3
"""Publish the trusted workflow result on its revalidated PR head, without PR code."""
import hashlib
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import sys

import dependency_inventory as inventory
import dependency_policy as policy
import dependency_review_provider as provider

ROOT=Path(__file__).resolve().parents[1]
CHECK_NAME='Dependency Policy'


class PublishError(ValueError):
    def __init__(self):super().__init__('cannot publish a verified trusted dependency check')


def require(value):
    if not value:raise PublishError()


def post_check(payload):
    environment={name:os.environ[name] for name in ('PATH','HOME','GH_TOKEN','GITHUB_TOKEN') if name in os.environ}
    environment.update(GH_PROMPT_DISABLED='1',GH_PAGER='cat',LC_ALL='C.UTF-8')
    return inventory._run(['gh','api','--hostname','github.com','--method','POST','--input','-',
        '-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10',
        'repos/aatuh/evydence/check-runs'],ROOT,environment,
        data=json.dumps(payload,sort_keys=True,separators=(',',':')).encode(),timeout=30)


def run(parent,api,*,post=post_check):
    try:
        require(parent.get('GITHUB_ACTIONS')=='true' and parent.get('GITHUB_EVENT_NAME')=='pull_request_target'
            and parent.get('GITHUB_REPOSITORY')=='aatuh/evydence' and parent.get('GITHUB_REF')=='refs/heads/master')
        base=provider.sha(parent['DEPENDENCY_TARGET_BASE']);head=provider.sha(parent['DEPENDENCY_SOURCE_COMMIT'])
        require(parent.get('GITHUB_SHA')==base and base!=head)
        number=parent['DEPENDENCY_PULL_REQUEST'];require(isinstance(number,str) and re.fullmatch(r'[1-9][0-9]{0,9}',number))
        number=provider.number(int(number));repository=provider.actions.repository(parent['DEPENDENCY_HEAD_REPOSITORY'])
        outcome=parent['DEPENDENCY_JOB_RESULT'];require(outcome in {'success','failure','cancelled','skipped'})
        run_id=parent['GITHUB_RUN_ID'];attempt=parent['GITHUB_RUN_ATTEMPT']
        require(all(isinstance(value,str) and re.fullmatch(r'[1-9][0-9]{0,19}',value) for value in (run_id,attempt)))
        current=provider.pull_context(api.get('pulls/'+str(number)),number)
        require(all(current[key]==value for key,value in {'base':base,'head':head,'head_repository':repository}.items()))
        same_day=parent.get('DEPENDENCY_ASSESSMENT_DAY')==datetime.now(timezone.utc).date().isoformat()
        conclusion='success' if outcome=='success' and same_day else 'failure'
        payload={'name':CHECK_NAME,'head_sha':head,'status':'completed','conclusion':conclusion,
            'external_id':'dependency-policy:'+base+':'+head+':'+run_id+':'+attempt,
            'details_url':'https://github.com/aatuh/evydence/actions/runs/'+run_id,
            'output':{'title':'Declared dependency admission '+('passed' if conclusion=='success' else 'did not pass'),
                'summary':'Trusted target-base evaluation. Base: '+base+'. Head: '+head+'. Evaluation job: '+outcome
                    +'. Assessment UTC day: '+('current' if same_day else 'missing or stale')+'.'}}
        raw=post(payload);require(isinstance(raw,bytes) and len(raw)<=policy.MAX_DOCUMENT_BYTES)
        result=policy.parse_document(raw)
        require(isinstance(result,dict) and type(result.get('id')) is int and result['id']>0
            and all(result.get(key)==payload[key] for key in ['name','head_sha','status','conclusion','external_id'])
            and result.get('app',{}).get('slug')=='github-actions'
            and type(result.get('app',{}).get('id')) is int and result['app']['id']==15368
            # Actions may replace the supplied workflow URL with this exact check URL.
            and result.get('details_url') in (payload['details_url'],
                'https://github.com/aatuh/evydence/runs/'+str(result['id'])))
        return {'check_id':result['id'],'head':head,'base':base,'conclusion':conclusion,
            'request_sha256':hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'response_sha256':hashlib.sha256(raw).hexdigest()}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise PublishError() from None


def main():
    try:
        require(not sys.argv[1:])
        result=run(os.environ,provider.GitHub())
        print('dependency-check: published check '+str(result['check_id'])+' ('+result['conclusion']+')')
        return 0
    except (OSError,ValueError,TypeError):
        print('dependency-check: refused stale, unavailable or untrusted publication context',file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())
