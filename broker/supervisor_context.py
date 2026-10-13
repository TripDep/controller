"""Metadata transport and causal invalidation. Never an asset/work PASS."""
import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

HEX=re.compile(r'[a-f0-9]{64}\Z')
PATHS={r:'governance/supervisor/context/'+r+'.json' for r in ('rescue','guardian')}
class Blocked(ValueError): pass
def need(v,r):
    if not v: raise Blocked(r)
def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def stamp(s):
    try: d=datetime.fromisoformat(s.replace('Z','+00:00'))
    except (ValueError,TypeError,AttributeError): raise Blocked('CONTEXT_TIME')
    need(d.tzinfo is not None,'CONTEXT_TIMEZONE');return d
def exact(v,keys,reason): need(isinstance(v,dict) and set(v)==set(keys),reason)
def ref(v,allow_unversioned=False):
    exact(v,('library_file_id','version','sha256'),'CONTEXT_LIBRARY_REF')
    need(isinstance(v['library_file_id'],str) and re.fullmatch(r'libfile_[a-f0-9]{32}',v['library_file_id']),'CONTEXT_LIBRARY_ID')
    need(((type(v['version']) is int and v['version']>=0) or (allow_unversioned and v['version'] is None)) and isinstance(v['sha256'],str) and HEX.fullmatch(v['sha256']),'CONTEXT_LIBRARY_VERSION_DIGEST')
def validate(v):
    exact(v,('schema','role','observation_id','observed_at','master','state','provider','checkpoint','dependencies','signals','provenance','advancement_authorized'),'CONTEXT_FIELDS')
    need(v['schema']=='gg-supervisor-context-v1' and v['role'] in PATHS,'CONTEXT_SCHEMA_ROLE')
    need(v['advancement_authorized'] is False and v['provenance']=='OPERATOR_LIBRARY_READBACK_NOT_GIT_VERIFIED_CONTENT','CONTEXT_CANNOT_AUTHORIZE')
    stamp(v['observed_at']);ref(v['master']);ref(v['state'])
    need(stamp(v['observed_at'])<=datetime.now(timezone.utc)+timedelta(minutes=5),'CONTEXT_OBSERVATION_FUTURE')
    exact(v['provider'],('automation_id_sha256','last_run_time','enabled'),'CONTEXT_PROVIDER_FIELDS')
    p=v['provider'];need(HEX.fullmatch(p['automation_id_sha256']) and type(p['enabled']) is bool,'CONTEXT_PROVIDER');stamp(p['last_run_time'])
    need(stamp(p['last_run_time'])<=stamp(v['observed_at']),'CONTEXT_PROVIDER_FUTURE')
    need(isinstance(v['dependencies'],dict) and all(HEX.fullmatch(k) and HEX.fullmatch(h) for k,h in v['dependencies'].items()),'CONTEXT_DEPENDENCIES')
    need(isinstance(v['signals'],list),'CONTEXT_SIGNALS')
    for s in v['signals']:
        exact(s,('dependency','status'),'CONTEXT_SIGNAL_FIELDS')
        need((s['dependency']=='GLOBAL' or HEX.fullmatch(s['dependency'])) and s['status'] in ('UNKNOWN','FAIL','REGRESSION','PENDING'),'CONTEXT_SIGNAL')
    cp=v['checkpoint'];exact(cp,('status','source','verification','run_id_sha256'),'CONTEXT_CHECKPOINT_FIELDS')
    need(cp['status'] in ('CLOSED_VERIFIED_OPERATOR_READBACK','PENDING','UNVERIFIED'),'CONTEXT_CHECKPOINT_STATUS')
    if cp['status']=='CLOSED_VERIFIED_OPERATOR_READBACK':
        ref(cp['source'],True);ref(cp['verification'],True);need(HEX.fullmatch(cp['run_id_sha256']),'CONTEXT_RUN_ID')
    else:
        need(cp['source'] is None and cp['verification'] is None and cp['run_id_sha256'] is None,'CONTEXT_PENDING_NOT_COMPLETE')
    need(v['observation_id']==digest({k:x for k,x in v.items() if k!='observation_id'}),'CONTEXT_OBSERVATION_DIGEST')
    return v
def assess(previous,current,work_dependencies,guardian_required=False):
    """Dependencies and requirement flag MUST come from canonical work context (C06)."""
    validate(current);need(type(guardian_required) is bool,'CONTEXT_GUARDIAN_POLICY')
    need(isinstance(work_dependencies,(list,tuple)) and all(isinstance(x,str) and HEX.fullmatch(x) for x in work_dependencies),'CONTEXT_WORK_DEPENDENCIES')
    changed=set();master_change=False
    if previous is not None:
        validate(previous);need(previous['role']==current['role'],'CONTEXT_ROLE_SWAP')
        need(stamp(current['observed_at'])>=stamp(previous['observed_at']),'CONTEXT_REPLAY')
        for k in ('master','state'):
            need(current[k]['library_file_id']==previous[k]['library_file_id'],'CONTEXT_AUTHORITY_SWAP')
            need(current[k]['version']>=previous[k]['version'],'CONTEXT_VERSION_REPLAY')
            need(current[k]['version']!=previous[k]['version'] or current[k]['sha256']==previous[k]['sha256'],'CONTEXT_SAME_VERSION_TAMPER')
        need(current['observed_at']!=previous['observed_at'] or current['observation_id']==previous['observation_id'],'CONTEXT_SAME_TIME_CONFLICT')
        master_change=current['master']['sha256']!=previous['master']['sha256']
        changed={k for k in set(previous['dependencies'])|set(current['dependencies']) if previous['dependencies'].get(k)!=current['dependencies'].get(k)}
    deps=set(work_dependencies);affected=deps & changed
    unknown=deps-set(current['dependencies'])
    for s in current['signals']:
        if s['dependency']=='GLOBAL': unknown.add('GLOBAL')
        elif s['dependency'] in deps: unknown.add(s['dependency'])
    if current['role']=='guardian' and guardian_required and current['checkpoint']['status']!='CLOSED_VERIFIED_OPERATOR_READBACK': unknown.add('GUARDIAN_UNVERIFIED')
    if unknown: action='STOP_RELEVANT_CONTEXT_UNKNOWN'
    elif master_change or affected: action='RECHECK_AFFECTED_CONTROLS'
    elif previous is None: action='INITIAL_CONTEXT_CAPTURED'
    else: action='CONTEXT_RECORDED_NO_RECHECK'
    return {'schema':'gg-context-result-v1','role':current['role'],'action':action,'affected_dependencies':sorted(affected),'unknown_dependencies':sorted(unknown),'master_changed':master_change,'observation_id':current['observation_id'],'checkpoint_status':current['checkpoint']['status'],'advancement_authorized':False,'evidence_contents_verified_by_git':False,'scope':'CONTEXT_TRANSPORT_AND_CAUSAL_INVALIDATION_ONLY'}
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--ref',required=True);p.add_argument('--prove-transitions',action='store_true');args=p.parse_args(argv)
    from broker_live_review import ReadOnlyAPI,decode_file
    repo=os.environ.get('GITHUB_REPOSITORY','')
    try:
        need(hashlib.sha256(repo.encode()).hexdigest()=='ba6c371db01f88a9a16e02a03d673f320bd3c04adc3ebdff97b2ef102a188e70','CONTEXT_REPOSITORY')
        need(re.fullmatch('[a-f0-9]{40}',args.ref),'CONTEXT_IMMUTABLE_REF')
        api=ReadOnlyAPI(os.environ['GH_REVIEW_TOKEN'],repo)
        for role,path in PATHS.items():
            raw=decode_file(api.call('GET','/contents/'+path+'?ref='+args.ref),path)
            need(len(raw)<=32000,'CONTEXT_TOO_LARGE');v=validate(json.loads(raw));need(v['role']==role,'CONTEXT_PATH_ROLE')
            result=assess(None,v,[])
            result.update({'receipt_sha256':hashlib.sha256(raw).hexdigest(),'repository_ref':args.ref})
            print('C05_CONTEXT_INGESTED:'+json.dumps(result,sort_keys=True))
        if args.prove_transitions:
            from test_supervisor_context import receipt,seal
            import copy
            old=receipt();new=copy.deepcopy(old);new['observed_at']='2020-10-13T19:00:00+00:00'
            new['state']['version']+=1;new['state']['sha256']='0'*64;new['dependencies']['e'*64]='0'*64;seal(new)
            unrelated=assess(old,new,['c'*64]);need(unrelated['action']=='CONTEXT_RECORDED_NO_RECHECK','UNRELATED_CHANGE_RESTARTED')
            new['dependencies']['c'*64]='0'*64;seal(new);relevant=assess(old,new,['c'*64]);need(relevant['action']=='RECHECK_AFFECTED_CONTROLS','RELEVANT_CHANGE_IGNORED')
            guardian=assess(None,receipt('guardian'),[],True);need(guardian['action']=='STOP_RELEVANT_CONTEXT_UNKNOWN','GUARDIAN_LAUNCH_ACCEPTED')
            print('C05_SYNTHETIC_TRANSITIONS:'+json.dumps({'unrelated':unrelated['action'],'relevant':relevant['action'],'guardian_launch_only':guardian['action'],'advancement_authorized':False},sort_keys=True))
        return 0
    except (ValueError,KeyError,TypeError,OSError) as e:
        print('C05_CONTEXT_BLOCKED:'+str(e));return 1
if __name__=='__main__':raise SystemExit(main())
