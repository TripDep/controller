"""Authenticate the existing Git Actions PR precheck, never authorize work.

Only live authenticated API reads are accepted by the operational interface.
A producer's JSON/file is not an authenticated receipt. This is C03B origin
verification; per-rule judgment and advancement remain C04-C07 dependencies.
"""
import hashlib
import json
import re
import argparse
import os
from pathlib import Path
from urllib import request, error, parse

from broker_live_review import ReadOnlyAPI, decode_file
from broker_authority_alignment_v4 import strict_json

PRIVATE_REPO_SHA = 'ba6c371db01f88a9a16e02a03d673f320bd3c04adc3ebdff97b2ef102a188e70'
WORKFLOW = '.github/workflows/gg-broker-auto-review.yml'
WORKFLOW_ID = 383250183
# Immutable workflow / public source pairs enrolled through verified PRs.
TRUSTED_ISSUERS = {'e9d02d4de5f2d53944b35f4d414e3726b8dc5c99':
                   '716d1da518830e2fda701b1d92abcdf47d4a830b'}
ACTION_PIN = '233cd9dcb383f9fc92d5334ef6aaa1ffb86f9f2e'
REQUIRED = {'run_id','job_id','run_attempt','workflow_head_sha','public_sha',
            'pr_number','head_sha','base_sha','master_sha256'}
SHA40 = re.compile(r'[a-f0-9]{40}\Z')
SHA64 = re.compile(r'[a-f0-9]{64}\Z')
TIMESTAMPED_JSON = re.compile(r'^\d{4}-\d\d-\d\dT\S+Z (\{.*\})$')

class Blocked(ValueError):
    pass

def require(value, reason):
    if not value:
        raise Blocked(reason)

def validate_request(expected):
    require(isinstance(expected,dict) and set(expected)==REQUIRED,'ORIGIN_REQUEST_SCHEMA')
    for field in ('run_id','job_id','run_attempt','pr_number'):
        require(type(expected[field]) is int and expected[field]>0,'ORIGIN_REQUEST_ID:'+field)
    for field in ('workflow_head_sha','public_sha','head_sha','base_sha'):
        require(isinstance(expected[field],str) and SHA40.fullmatch(expected[field]),'ORIGIN_REQUEST_SHA:'+field)
    require(isinstance(expected['master_sha256'],str) and SHA64.fullmatch(expected['master_sha256']),'ORIGIN_REQUEST_MASTER')

def fingerprint(run):
    return (tuple(run.get(k) for k in ('id','run_attempt','head_sha','head_branch','status','conclusion','path','event','workflow_id')),
            run.get('repository',{}).get('full_name'),run.get('head_repository',{}).get('full_name'))

def extract_precheck(logs):
    require(isinstance(logs,str) and len(logs.encode())<=4*1024*1024,'ORIGIN_LOG_SIZE')
    results=[]
    for line in logs.splitlines():
        match=TIMESTAMPED_JSON.fullmatch(line)
        if match:
            value=strict_json(match.group(1).encode(),max_size=65536)
            if isinstance(value,dict) and value.get('status')=='ROUTINE_PRECHECK_PASS_ONLY':
                results.append(value)
    require(len(results)==1,'ORIGIN_RESULT_NOT_UNIQUE')
    return results[0]

def verify_git_origin(api, expected):
    """api is the authenticated fixed-repository GET client, not PR input.

    A fixture API may be injected by tests; those tests are never live evidence.
    Run and job metadata are read from GitHub, not accepted in the request.
    """
    validate_request(expected)
    require(hashlib.sha256(api.repository.encode()).hexdigest()==PRIVATE_REPO_SHA,'ORIGIN_REPOSITORY')
    route='/actions/runs/'+str(expected['run_id'])
    run=api.call('GET',route)
    require(isinstance(run,dict),'ORIGIN_RUN_INVALID')
    for field, wanted in {'id':expected['run_id'],'run_attempt':expected['run_attempt'],
            'head_sha':expected['workflow_head_sha'],'head_branch':'main',
            'status':'completed','conclusion':'success','event':'workflow_run',
            'path':WORKFLOW,'workflow_id':WORKFLOW_ID}.items():
        require(type(run.get(field)) is type(wanted) and run.get(field)==wanted,'ORIGIN_RUN_MISMATCH:'+field)
    for field in ('repository','head_repository'):
        require(run.get(field,{}).get('full_name')==api.repository,'ORIGIN_CROSS_REPOSITORY')
    source_record=api.call('GET','/contents/'+WORKFLOW+'?ref='+expected['workflow_head_sha'])
    source=decode_file(source_record,WORKFLOW)
    public_sha=TRUSTED_ISSUERS.get(source_record.get('sha'))
    require(public_sha is not None and public_sha==expected['public_sha'],'ORIGIN_UNENROLLED_ISSUER')
    refs=re.findall(rb'(?m)^\s+ref: ([a-f0-9]{40})\s*$',source)
    cli_pins=re.findall(rb'--public-sha ([a-f0-9]{40})',source)
    require(refs==[public_sha.encode()] and cli_pins==[public_sha.encode()]*2,'ORIGIN_SOURCE_PIN')
    jobs=api.call('GET',route+'/attempts/'+str(expected['run_attempt'])+'/jobs?per_page=100')
    require(isinstance(jobs,dict) and isinstance(jobs.get('jobs'),list)
            and type(jobs.get('total_count')) is int
            and jobs['total_count']==len(jobs['jobs']) and len(jobs['jobs'])<=100,'ORIGIN_JOBS_INCOMPLETE')
    selected=[j for j in jobs['jobs'] if j.get('name')=='automatic-review']
    require(len(selected)==1,'ORIGIN_JOB_NOT_UNIQUE')
    job=selected[0]
    for field,wanted in {'id':expected['job_id'],'run_id':expected['run_id'],
            'head_sha':expected['workflow_head_sha'],'status':'completed','conclusion':'success'}.items():
        require(job.get(field)==wanted,'ORIGIN_JOB_MISMATCH:'+field)
    steps=[s for s in job.get('steps',[]) if s.get('name')=='Check actual PR sources, checks and completed workflow provenance']
    require(len(steps)==1 and steps[0].get('status')=='completed'
            and steps[0].get('conclusion')=='success','ORIGIN_VALIDATOR_STEP')
    result=extract_precheck(api.job_logs(expected['job_id']))
    for field,wanted in {'pr_number':expected['pr_number'],'pr_head_sha':expected['head_sha'],
            'master_sha256':expected['master_sha256'],'public_controller_sha':ACTION_PIN,
            'authority_mode':'PINNED_LIBRARY_SNAPSHOT'}.items():
        require(result.get(field)==wanted,'ORIGIN_RESULT_BINDING:'+field)
    for field in ('merge_authorized','broker_enabled','library_live_read','private_write_isolation_verified'):
        require(result.get(field) is False,'ORIGIN_SCOPE_ESCALATION:'+field)
    pr=api.call('GET','/pulls/'+str(expected['pr_number']))
    require(pr.get('number')==expected['pr_number'],'ORIGIN_PR_NUMBER')
    for field,sha in (('head',expected['head_sha']),('base',expected['base_sha'])):
        require(pr.get(field,{}).get('sha')==sha
                and pr.get(field,{}).get('repo',{}).get('full_name')==api.repository,'ORIGIN_PR_MOVED:'+field)
    last=api.call('GET',route)
    require(fingerprint(last)==fingerprint(run),'ORIGIN_RUN_CHANGED')
    return {'schema':'gg-git-judgment-origin-v1','status':'AUTHENTIC_GITHUB_PR_PRECHECK',
            'binding':dict(expected),'workflow_blob':source_record['sha'],
            'result_sha256':hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'scope':'PR_PRECHECK_ORIGIN_ONLY','historical_proof_only':True,
            'advancement_authorized':False,'all_families_verified':False,
            'canonical_library_live_verified':False,'merge_authorized':False}

class NoFollow(request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None

class OriginAPI(ReadOnlyAPI):
    def job_logs(self, job_id):
        require(type(job_id) is int and job_id>0,'ORIGIN_LOG_JOB_ID')
        url='https://api.github.com/repos/'+self.repository+'/actions/jobs/'+str(job_id)+'/logs'
        initial=request.Request(url,headers={'Accept':'application/vnd.github+json',
            'Authorization':'Bearer '+self.token,'X-GitHub-Api-Version':'2022-11-28'},method='GET')
        opener=request.build_opener(NoFollow())
        try:
            try:
                response=opener.open(initial,timeout=20)
            except error.HTTPError as exc:
                require(exc.code==302,'ORIGIN_LOG_API_UNAVAILABLE')
                location=exc.headers.get('Location','');target=parse.urlsplit(location)
                require(target.scheme=='https' and target.hostname and not target.username
                        and not target.password and target.port in (None,443) and not target.fragment
                        and (target.hostname.endswith('.blob.core.windows.net')
                             or target.hostname.endswith('.actions.githubusercontent.com')),
                        'ORIGIN_LOG_REDIRECT_HOST')
                # Separate request: never propagate the GitHub bearer or other
                # original headers to signed storage. Further redirects denied.
                response=opener.open(request.Request(location,method='GET'),timeout=20)
            with response:
                raw=response.read(4*1024*1024+1)
            require(len(raw)<=4*1024*1024,'ORIGIN_LOG_SIZE')
            return raw.decode('utf-8',errors='strict')
        except (error.HTTPError,error.URLError,OSError,UnicodeError) as exc:
            raise Blocked('ORIGIN_LOG_UNAVAILABLE:'+type(exc).__name__) from exc

def require_work_advancement(receipt):
    # The legacy PR precheck cannot be promoted into a phase/rule/MG0 verdict.
    raise Blocked('PER_RULE_JUDGMENT_AND_COVERAGE_REQUIRED')

def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--repository',required=True);args=parser.parse_args(argv)
    try:
        expected=strict_json(args.request.read_bytes(),max_size=65536)
        api=OriginAPI(os.environ.get('GH_REVIEW_TOKEN'),args.repository)
        print(json.dumps(verify_git_origin(api,expected),sort_keys=True))
        return 0
    except (ValueError,KeyError,TypeError,OSError) as exc:
        print('GIT_ORIGIN_BLOCKED:'+str(exc))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
