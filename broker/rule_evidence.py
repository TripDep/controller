"""Retrieve native evidence and bind it to canonical rule/phase/MG0/attempt.

Binding verification is not rule semantic judgment or asset advancement (C07).
No local producer JSON is ever accepted as an authenticated native result.
"""
import argparse
import hashlib
import json
import os
import re
from git_judgment_origin import OriginAPI, fingerprint, WORKFLOW, WORKFLOW_ID, PRIVATE_REPO_SHA
from broker_live_review import decode_file
from broker_authority_alignment_v4 import strict_json
import family_coverage as coverage

SHA=re.compile('[a-f0-9]{64}\\Z');SHA40=re.compile('[a-f0-9]{40}\\Z')
CASE='governance/supervisor/evidence/c06-linkage-case.json'
SCOPE='GOVERNANCE_EVIDENCE_LINKAGE_TEST_ONLY'
EMIT_STEP='Emit C06 canonical rule attempt phase and MG0 linkage proof'
CONTEXT_STEP='Ingest Rescue Guardian context without granting work authorization'
PREFIX='C06_BOUND_RULE_EVIDENCE:'
class Blocked(ValueError):pass
def need(v,r):
    if not v:raise Blocked(r)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()
def exact(v,keys,r):need(isinstance(v,dict) and set(v)==set(keys),r)
def is_sha(v):return isinstance(v,str) and SHA.fullmatch(v)
def binding(v):
    exact(v,('work_item_sha256','attempt_id','attempt_number','previous_attempt_id','phase','family','rule_id','master_sha256','source_sha256','requirement_sha256','rescue_observation_id','guardian_observation_id','work_dependencies','context_scope'),'EVIDENCE_BINDING_SCHEMA')
    for k in ('work_item_sha256','attempt_id','master_sha256','source_sha256','requirement_sha256','rescue_observation_id','guardian_observation_id'):need(is_sha(v[k]),'EVIDENCE_BINDING_DIGEST:'+k)
    need(type(v['attempt_number']) is int and v['attempt_number']>0,'EVIDENCE_ATTEMPT_NUMBER')
    need((v['attempt_number']==1 and v['previous_attempt_id'] is None) or (v['attempt_number']>1 and is_sha(v['previous_attempt_id']) and v['previous_attempt_id']!=v['attempt_id']),'EVIDENCE_CORRECTION_CHAIN')
    need(v['phase'] in coverage.PHASES and isinstance(v['rule_id'],str) and isinstance(v['family'],str),'EVIDENCE_RULE_PHASE')
    need(v['context_scope']==SCOPE,'EVIDENCE_SCOPE_NOT_ENROLLED')
    need(isinstance(v['work_dependencies'],dict) and v['work_dependencies'] and all(is_sha(k) and is_sha(h) for k,h in v['work_dependencies'].items()),'EVIDENCE_DEPENDENCY_BINDINGS')
def extract(logs,prefix):
    need(isinstance(logs,str) and len(logs.encode())<=4*1024*1024,'EVIDENCE_LOG_SIZE')
    values=[]
    for line in logs.splitlines():
        m=re.fullmatch(r'\d{4}-\d\d-\d\dT\S+Z '+re.escape(prefix)+r'(\{.*\})',line)
        if m:values.append(strict_json(m.group(1).encode(),max_size=65536))
    need(len(values)==1,'EVIDENCE_RESULT_NOT_UNIQUE');return values[0]
def native(api,origin,issuer,step):
    """issuer comes from protected, reviewed consumer config, never the producer."""
    exact(origin,('run_id','job_id','run_attempt','head_sha'),'EVIDENCE_ORIGIN_SCHEMA')
    exact(issuer,('workflow_blob','public_sha'),'EVIDENCE_ISSUER_SCHEMA')
    for k in ('run_id','job_id','run_attempt'):need(type(origin[k]) is int and origin[k]>0,'EVIDENCE_NATIVE_ID')
    need(isinstance(origin['head_sha'],str) and SHA40.fullmatch(origin['head_sha']) and all(isinstance(issuer[k],str) and SHA40.fullmatch(issuer[k]) for k in issuer),'EVIDENCE_NATIVE_SHA')
    need(hashlib.sha256(api.repository.encode()).hexdigest()==PRIVATE_REPO_SHA,'EVIDENCE_REPOSITORY')
    route='/actions/runs/'+str(origin['run_id']);run=api.call('GET',route)
    fields={'id':origin['run_id'],'run_attempt':origin['run_attempt'],'head_sha':origin['head_sha'],'head_branch':'main','status':'completed','conclusion':'success','event':'workflow_run','path':WORKFLOW,'workflow_id':WORKFLOW_ID}
    for k,w in fields.items():need(type(run.get(k)) is type(w) and run[k]==w,'EVIDENCE_RUN:'+k)
    for k in ('repository','head_repository'):need(run.get(k,{}).get('full_name')==api.repository,'EVIDENCE_CROSS_REPO')
    source=api.call('GET','/contents/'+WORKFLOW+'?ref='+origin['head_sha']);raw=decode_file(source,WORKFLOW)
    need(source.get('sha')==issuer['workflow_blob'],'EVIDENCE_UNENROLLED_ISSUER')
    need(re.findall(rb'(?m)^\s+ref: ([a-f0-9]{40})\s*$',raw)==[issuer['public_sha'].encode()],'EVIDENCE_PUBLIC_PIN')
    jobs=api.call('GET',route+'/attempts/'+str(origin['run_attempt'])+'/jobs?per_page=100')
    need(isinstance(jobs,dict) and type(jobs.get('total_count')) is int and isinstance(jobs.get('jobs'),list) and jobs['total_count']==len(jobs['jobs'])<=100,'EVIDENCE_JOB_PAGE')
    selected=[j for j in jobs['jobs'] if j.get('name')=='automatic-review'];need(len(selected)==1,'EVIDENCE_JOB_UNIQUE');job=selected[0]
    for k,w in {'id':origin['job_id'],'run_id':origin['run_id'],'head_sha':origin['head_sha'],'status':'completed','conclusion':'success'}.items():need(type(job.get(k)) is type(w) and job[k]==w,'EVIDENCE_JOB:'+k)
    steps=[s for s in job.get('steps',[]) if s.get('name')==step];need(len(steps)==1 and steps[0].get('status')=='completed' and steps[0].get('conclusion')=='success','EVIDENCE_STEP')
    logs=api.job_logs(origin['job_id']);need(fingerprint(api.call('GET',route))==fingerprint(run),'EVIDENCE_RUN_CHANGED')
    return logs
def validate_packet(packet,expected):
    binding(expected);exact(packet,('schema','scope','binding','evidence','mg0','advancement_authorized'),'EVIDENCE_PACKET_SCHEMA')
    need(packet['schema']=='gg-bound-rule-evidence-v1' and packet['scope']==SCOPE and packet['advancement_authorized'] is False,'EVIDENCE_PACKET_SCOPE')
    need(packet['binding']==expected,'EVIDENCE_ATTEMPT_OR_CONTEXT_MISMATCH')
    exact(packet['evidence'],('kind','result','content_sha256','observations','native_origin'),'EVIDENCE_CONTENT_SCHEMA')
    e=packet['evidence'];need(e['kind']=='NATIVE_CONTEXT_TRANSPORT_TEST' and e['result']=='LINKAGE_CHECKED_ONLY' and e['content_sha256']==digest(e['observations']),'EVIDENCE_CONTENT_DIGEST')
    exact(packet['mg0'],('binding','kind','result','trigger_assessment','content_sha256'),'EVIDENCE_MG0_REQUIRED')
    mg=packet['mg0'];need(mg['binding']==expected and mg['kind']=='INDIVIDUAL_PROCESS_PROOF_BINDING' and mg['result']=='BINDING_CHECKED_NOT_MG0_PASS','EVIDENCE_MG0_BINDING')
    need(isinstance(mg['trigger_assessment'],dict) and mg['content_sha256']==digest(mg['trigger_assessment']),'EVIDENCE_MG0_CONTENT')
    return {'schema':'gg-evidence-link-result-v1','status':'BINDING_STRUCTURE_VERIFIED_ONLY','binding':expected,'packet_sha256':digest(packet),'rule_evidence_sha256':e['content_sha256'],'mg0_evidence_sha256':mg['content_sha256'],'native_content_retrieved':False,'rule_semantics_verified':False,'mg0_execution_pass':False,'asset_execution_passes':0,'advancement_authorized':False,'scope':SCOPE}
def verify(api,origin,issuer,expected):
    packet=extract(native(api,origin,issuer,EMIT_STEP),PREFIX)
    result=validate_packet(packet,expected)
    result.update(status='NATIVE_EVIDENCE_CONTENT_AND_BINDING_VERIFIED',native_content_retrieved=True)
    return result
def emit(api,ref):
    need(isinstance(ref,str) and SHA40.fullmatch(ref),'EVIDENCE_CASE_REF')
    case=strict_json(decode_file(api.call('GET','/contents/'+CASE+'?ref='+ref),CASE),max_size=65536)
    exact(case,('binding','context_origin','context_issuer'),'EVIDENCE_CASE_SCHEMA');b=case['binding'];binding(b)
    raw={k:decode_file(api.call('GET','/contents/'+p+'?ref='+ref),p) for k,p in coverage.SOURCES.items()};inv=coverage.build_inventory(raw,b['master_sha256']);row=inv['rules'].get(b['rule_id'])
    need(row and row['family']==b['family'] and row['source_sha256']==b['source_sha256'] and row['requirement_sha256']==b['requirement_sha256'],'EVIDENCE_CANONICAL_RULE')
    # Only the reviewed context-test issuer is enrolled here. Never enroll an
    # arbitrary producer-supplied issuer or promote this test into asset QA.
    trusted={'workflow_blob':'83143d29144ff51ed4b99940df83087773ff0983','public_sha':'ee7a810676797bd4677ab988f579be6375ab58bf'}
    need(case['context_issuer']==trusted,'EVIDENCE_CONTEXT_ISSUER')
    logs=native(api,case['context_origin'],trusted,CONTEXT_STEP)
    observations=[]
    for role in ('rescue','guardian'):
        matches=[]
        for line in logs.splitlines():
            if re.match(r'^\d{4}-\d\d-\d\dT\S+Z C05_CONTEXT_INGESTED:',line):
                x=strict_json(line.split('C05_CONTEXT_INGESTED:',1)[1].encode(),max_size=65536)
                if x.get('role')==role:matches.append(x)
        need(len(matches)==1,'EVIDENCE_CONTEXT_UNIQUE');x=matches[0]
        need(x.get('observation_id')==b[role+'_observation_id'] and x.get('advancement_authorized') is False and x.get('evidence_contents_verified_by_git') is False,'EVIDENCE_CONTEXT_BINDING')
        path='governance/supervisor/context/'+role+'.json';source=decode_file(api.call('GET','/contents/'+path+'?ref='+x['repository_ref']),path)
        need(hashlib.sha256(source).hexdigest()==x['receipt_sha256'],'EVIDENCE_CONTEXT_CONTENT')
        from supervisor_context import validate
        context=validate(strict_json(source,max_size=32000));need(context['master']['sha256']==b['master_sha256'],'EVIDENCE_CONTEXT_MASTER')
        need(all(context['dependencies'].get(k)==h for k,h in b['work_dependencies'].items()),'EVIDENCE_CONTEXT_DEPENDENCIES')
        observations.append(x)
    checks=extract(logs,'C05_SYNTHETIC_TRANSITIONS:')
    need(checks=={'advancement_authorized':False,'guardian_launch_only':'STOP_RELEVANT_CONTEXT_UNKNOWN','relevant':'RECHECK_AFFECTED_CONTROLS','unrelated':'CONTEXT_RECORDED_NO_RECHECK'},'EVIDENCE_NATIVE_CHECK_CONTENT')
    assessment={'canonical_mg0_source_sha256':inv['rules']['MG0']['source_sha256'],'canonical_mg0_requirement_sha256':inv['rules']['MG0']['requirement_sha256'],'observed_process_checks':checks,'trigger_analysis_scope':'CONTEXT_LINKAGE_TEST_ONLY_FULL_MG0_EXECUTION_UNVERIFIED'}
    packet={'schema':'gg-bound-rule-evidence-v1','scope':SCOPE,'binding':b,'evidence':{'kind':'NATIVE_CONTEXT_TRANSPORT_TEST','result':'LINKAGE_CHECKED_ONLY','content_sha256':digest(observations),'observations':observations,'native_origin':case['context_origin']},'mg0':{'binding':b,'kind':'INDIVIDUAL_PROCESS_PROOF_BINDING','result':'BINDING_CHECKED_NOT_MG0_PASS','trigger_assessment':assessment,'content_sha256':digest(assessment)},'advancement_authorized':False}
    validate_packet(packet,b);print(PREFIX+json.dumps(packet,sort_keys=True));return packet
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--emit-ref');p.add_argument('--verify-run',type=int);p.add_argument('--verify-job',type=int);p.add_argument('--verify-head');p.add_argument('--issuer-blob');p.add_argument('--issuer-public');p.add_argument('--case-ref');args=p.parse_args(argv)
    try:
        api=OriginAPI(os.environ['GH_REVIEW_TOKEN'],os.environ['GITHUB_REPOSITORY'])
        if args.emit_ref:emit(api,args.emit_ref)
        else:
            need(args.case_ref and SHA40.fullmatch(args.case_ref),'EVIDENCE_EXPECTED_CASE_REF')
            case=strict_json(decode_file(api.call('GET','/contents/'+CASE+'?ref='+args.case_ref),CASE),max_size=65536)
            o={'run_id':args.verify_run,'job_id':args.verify_job,'run_attempt':1,'head_sha':args.verify_head};issuer={'workflow_blob':args.issuer_blob,'public_sha':args.issuer_public};result=verify(api,o,issuer,case['binding']);print('C06_NATIVE_EVIDENCE_VERIFIED:'+json.dumps(result,sort_keys=True))
            import copy
            wrong=copy.deepcopy(case['binding']);wrong['attempt_id']='f'*64
            try:verify(api,o,issuer,wrong)
            except Blocked as exc:need(str(exc)=='EVIDENCE_ATTEMPT_OR_CONTEXT_MISMATCH','EVIDENCE_NEGATIVE_REASON');print('C06_WRONG_ATTEMPT_REJECTED:'+str(exc))
            else:raise Blocked('EVIDENCE_WRONG_ATTEMPT_ACCEPTED')
        return 0
    except (ValueError,KeyError,TypeError,OSError) as exc:print('C06_EVIDENCE_BLOCKED:'+str(exc));return 1
if __name__=='__main__':raise SystemExit(main())
