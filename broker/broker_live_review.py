"""Read-only live PR review; pinned Library snapshot, never a merge authority."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys

import broker_auto_review_v4 as auto
import git_release_broker_v2 as base
import broker_authority_alignment_v4 as alignment

PUBLIC = 'TripDep/controller'
RULESET = 24958898
WORKFLOW = '.github/workflows/gg-phase-guard.yml'
MASTER = 'governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md'
HEX40 = re.compile(r'[0-9a-f]{40}\Z')

class ReadOnlyAPI(base.GitHubAPI):
    def call(self, method, route, payload=None):
        if method != 'GET' or payload is not None:
            raise auto.Blocked('READ_ONLY_API_WRITE_FORBIDDEN')
        if not isinstance(route, str) or not route.startswith('/') or '://' in route or '..' in route or any(c in route for c in '\r\n'):
            raise auto.Blocked('READ_ONLY_API_ROUTE_INVALID')
        return super().call(method, route)
    def merge(self, *args):
        raise auto.Blocked('READ_ONLY_API_MERGE_FORBIDDEN')

def decode_file(item, path, maximum=3000000):
    if not isinstance(item, dict) or item.get('type') != 'file' or item.get('path') != path or item.get('encoding') != 'base64':
        raise auto.Blocked('PINNED_SOURCE_RECORD_INVALID')
    encoded=item.get('content')
    if not isinstance(encoded,str) or len(encoded)>maximum*2:
        raise auto.Blocked('PINNED_SOURCE_TOO_LARGE')
    try:
        raw=base64.b64decode(''.join(encoded.split()),validate=True)
    except (ValueError,TypeError):
        raise auto.Blocked('PINNED_SOURCE_ENCODING_INVALID')
    if len(raw)>maximum:
        raise auto.Blocked('PINNED_SOURCE_TOO_LARGE')
    blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if item.get('sha') != blob:
        raise auto.Blocked('PINNED_SOURCE_BLOB_MISMATCH')
    return raw

def workflow_pin(raw):
    matches=re.findall(rb'(?m)^\s*(?:-\s*)?uses:\s*TripDep/controller@([0-9a-f]{40})\s*$',raw)
    if len(matches)!=1:
        raise auto.Blocked('PRIVATE_ACTION_PIN_MISSING_OR_AMBIGUOUS')
    return matches[0].decode()

def event_pr_numbers(event, repo):
    run=event.get('workflow_run') if isinstance(event,dict) else None
    if not isinstance(run,dict) or run.get('name')!='Golden Garden mandatory phase guard' or run.get('path')!=WORKFLOW:
        raise auto.Blocked('UNTRUSTED_UPSTREAM_WORKFLOW')
    if run.get('status')!='completed' or run.get('conclusion')!='success':
        raise auto.Blocked('UPSTREAM_NOT_SUCCESS')
    if run.get('repository',{}).get('full_name')!=repo or run.get('head_repository',{}).get('full_name')!=repo:
        raise auto.Blocked('UPSTREAM_REPOSITORY_MISMATCH')
    if run.get('event')!='pull_request':
        return []
    rows=run.get('pull_requests')
    if not isinstance(rows,list) or len(rows)!=1:
        raise auto.Blocked('UPSTREAM_PR_NOT_UNIQUE')
    number=rows[0].get('number') if isinstance(rows[0],dict) else None
    if type(number) is not int or number<1:
        raise auto.Blocked('UPSTREAM_PR_NUMBER_INVALID')
    return [number]

def review(private_api, public_api, number, public_sha):
    policy=alignment.strict_json(decode_file(public_api.call('GET','/contents/broker/broker_policy.json?ref='+public_sha),'broker/broker_policy.json'))
    supervisor=alignment.strict_json(decode_file(public_api.call('GET','/contents/supervisor/policy.json?ref='+public_sha),'supervisor/policy.json'))
    pr=private_api.call('GET',f'/pulls/{number}')
    base_sha=pr.get('base',{}).get('sha')
    if not isinstance(base_sha,str) or not HEX40.fullmatch(base_sha):
        raise auto.Blocked('PRIVATE_BASE_SHA_INVALID')
    snapshot=decode_file(private_api.call('GET','/contents/'+MASTER+'?ref='+base_sha),MASTER)
    if hashlib.sha256(snapshot).hexdigest()!=policy['master_sha256'] or policy['master_sha256']!=supervisor['canonical_master_sha256']:
        raise auto.Blocked('LIBRARY_PINNED_SNAPSHOT_DRIFT')
    source=decode_file(private_api.call('GET','/contents/'+WORKFLOW+'?ref='+base_sha),WORKFLOW)
    result=auto.assess_routine_eligibility(canonical_master=snapshot,private_master=snapshot,
        supervisor_policy=supervisor,broker_policy=policy,
        public_branch=public_api.call('GET','/branches/main'),
        public_ruleset=public_api.call('GET','/rulesets/'+str(RULESET)),
        private_api=private_api,pr_number=number,pinned_public_main_sha=public_sha,
        private_workflow_action_sha=workflow_pin(source))
    result.update({'authority_mode':'PINNED_LIBRARY_SNAPSHOT','library_live_read':False,
                   'merge_authorized':False,'private_write_isolation_verified':False})
    return result

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--public-sha',required=True)
    parser.add_argument('--pr-number',type=int)
    args=parser.parse_args(argv)
    try:
        if not HEX40.fullmatch(args.public_sha):
            raise auto.Blocked('PUBLIC_SOURCE_SHA_INVALID')
        repo=os.environ.get('GITHUB_REPOSITORY','')
        if hashlib.sha256(repo.encode()).hexdigest()!='ba6c371db01f88a9a16e02a03d673f320bd3c04adc3ebdff97b2ef102a188e70':
            raise auto.Blocked('PRIVATE_REPOSITORY_NOT_PINNED')
        token=os.environ.get('GH_REVIEW_TOKEN')
        private=ReadOnlyAPI(token,repo);public=ReadOnlyAPI(token,PUBLIC)
        if args.pr_number is not None:
            numbers=[args.pr_number]
        else:
            event=alignment.strict_json(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes(),max_size=1000000)
            numbers=event_pr_numbers(event,repo)
        if not numbers:
            print('NO_PR_EVENT: no review or merge authorized')
        for number in numbers:
            result=review(private,public,number,args.public_sha)
            print(json.dumps(result,sort_keys=True))
        return 0
    except (auto.Blocked,base.Blocked,alignment.Blocked,KeyError,ValueError,TypeError,OSError) as exc:
        print('LIVE_REVIEW_BLOCKED:'+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
