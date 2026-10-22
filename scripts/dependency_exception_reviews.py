#!/usr/bin/env python3
"""Read owner-authored exact-scope exception approvals; never create messages."""
from datetime import datetime,timezone
import hashlib
import json
import re
from urllib.parse import urlsplit

import dependency_policy as policy

SCHEMA='evydence-dependency-exception-review.v1'
REVIEWERS={'aatuh'}
MAX_BODY_BYTES=16*1024


class ReviewError(ValueError):
    def __init__(self):super().__init__('missing or invalid authenticated exact-scope exception review')


def require(value):
    if not value:raise ReviewError()


def approval_payload(exception):
    require(isinstance(exception,dict) and set(exception)==policy.EXCEPTION_KEYS)
    # The comment/review ID does not exist until publication. All material
    # scope, responsibility, reason and date fields are bound, excluding its URL.
    value={key:value for key,value in exception.items() if key!='review_url'}
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    require(len(raw)<=8192)
    return {'schema':SCHEMA,'action':'approve','exception_sha256':hashlib.sha256(raw).hexdigest()}


def instant(value):
    require(isinstance(value,str) and 0<len(value)<=64)
    result=datetime.fromisoformat(value.replace('Z','+00:00'));require(result.tzinfo is not None)
    return result.astimezone(timezone.utc)


def verify(rules,api,today):
    try:
        rules=policy.validate_policy(rules,today);result=[]
        for row in rules['exceptions']:
            require(api is not None)
            reference=urlsplit(row['review_url'])
            parent=re.fullmatch(r'/aatuh/evydence/pull/([1-9][0-9]*)',reference.path)
            fragment=re.fullmatch(r'(issuecomment|pullrequestreview)-([1-9][0-9]*)',reference.fragment)
            require(parent is not None and fragment is not None)
            pull,kind,identity=parent[1],fragment[1],fragment[2]
            endpoint='issues/comments/'+identity if kind=='issuecomment' else 'pulls/'+pull+'/reviews/'+identity
            data=api.get(endpoint)
            require(api.authenticated is True and isinstance(data,dict)
                    and type(data.get('id')) is int and data['id']==int(identity)
                    and data.get('html_url')==row['review_url']
                    and data.get('author_association')=='OWNER'
                    and data.get('performed_via_github_app') is None)
            user=data.get('user');require(isinstance(user,dict) and user.get('type')=='User'
                                         and isinstance(user.get('login'),str) and user['login'].lower() in REVIEWERS)
            if kind=='issuecomment':
                require(data.get('issue_url')=='https://api.github.com/repos/aatuh/evydence/issues/'+pull)
                reviewed=instant(data.get('updated_at'));require(instant(data.get('created_at'))<=reviewed)
            else:
                require(data.get('pull_request_url')=='https://api.github.com/repos/aatuh/evydence/pulls/'+pull
                        and data.get('state')=='APPROVED')
                reviewed=instant(data.get('submitted_at'))
            require(reviewed.date().isoformat()==row['reviewed_on'] and reviewed.date()<=today)
            body=data.get('body');require(isinstance(body,str) and len(body.encode('utf-8'))<=MAX_BODY_BYTES)
            require(policy.parse_document(body.encode('utf-8'))==approval_payload(row))
            result.append({'exception_id':row['id'],'review_url':row['review_url'],
                           'reviewer':user['login'].lower(),'reviewed_at':reviewed.isoformat(),
                           'approval_sha256':hashlib.sha256(body.encode('utf-8')).hexdigest()})
        return result
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ReviewError() from None
