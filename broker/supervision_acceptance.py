"""C08 adverse-request tests and C09 readiness, using actual native Git evidence.

Counterfactual inputs are labelled tests. No asset state, source or native
issuer output is modified. A transport recovery is not an eligible work advance.
"""
import argparse
import copy
import json
import os
import re
from datetime import datetime, timedelta

import family_coverage as coverage
import planning_semantics as planning
import supervisor_judgment as judgment
from broker_live_review import decode_file
from git_judgment_origin import OriginAPI, PRIVATE_REPO_SHA

EMITTER = {'run_id':38552491060,'job_id':115813547028,'run_attempt':1,
           'head_sha':'c120fa9bc595cd3a922bb43af2d184615377ab38'}
EMITTER_ISSUER = {'workflow_blob':'b020a19e0e6b496199bc05c89a4f121e40952976',
                  'public_sha':'269805cbf8a046c628927b95e73fd284d1053a9a'}
DECISION = {'run_id':38552856566,'job_id':115814749128,'run_attempt':1,
            'head_sha':'740f7e068dd73cd05ce7860a009cdf48e126e481'}
DECISION_ISSUER = {'workflow_blob':'27ac0d22cbea93112b84ab0ec2fe6531a186e877',
                   'public_sha':'269805cbf8a046c628927b95e73fd284d1053a9a'}
CASE_POLICY = 'governance/supervisor/reviews/r165/policy.json'


def one_packet(logs, prefix):
    values=[]
    for line in logs.splitlines():
        match=re.fullmatch(r'\d{4}-\d\d-\d\dT\S+Z '+re.escape(prefix)+r'(\{.*\})',line)
        if match:values.append(judgment.evidence.strict_json(match.group(1).encode(),max_size=1500000))
    judgment.need(len(values)==1,'ACCEPTANCE_NATIVE_PACKET_UNIQUE')
    return values[0]


def load_case(api, ref, master_sha):
    def fetch(path, at=ref):
        return decode_file(api.call('GET','/contents/'+path+'?ref='+at),path)
    raw={key:fetch(path) for key,path in coverage.SOURCES.items()}
    inv=coverage.build_inventory(raw,master_sha)
    policy=judgment.evidence.strict_json(fetch(CASE_POLICY),max_size=32000)
    judgment.need(policy['work']['master_sha256']==master_sha,'ACCEPTANCE_CURRENT_MASTER')
    docs={}
    for key,spec in policy['inputs'].items():
        docs[key]=fetch(spec['path'],spec.get('ref',ref))
        judgment.need(planning.sha(docs[key])==spec['sha256'],'ACCEPTANCE_INPUT_DIGEST:'+key)
    packet,_=planning.documented_engine(inv,policy['work'],docs,policy['engine'])
    logs=judgment.evidence.native(api,EMITTER,EMITTER_ISSUER,judgment.SEMANTIC_STEP)
    judgment.need(one_packet(logs,judgment.PREFIX)==packet,'ACCEPTANCE_SOURCE_RECOMPUTATION')
    spec={'requirement_sha256':policy['engine']['requirement_sha256'],
          'validator_id':planning.VALIDATOR,'criteria':planning.CRITERIA,
          'issuer':EMITTER_ISSUER, 'source_ref':ref}
    backend=judgment.NativeRuleBackend(api,{planning.ENGINE_RULE:spec})
    offers={planning.ENGINE_RULE:{'native_origin':EMITTER,'expected_packet_sha256':judgment.digest(packet)}}
    contexts={role:planning.context_value(fetch(path)) for role,path in judgment.context.PATHS.items()}
    return inv,policy,docs,packet,spec,backend,offers,contexts


def expected_rejection(call, reason):
    try:call()
    except ValueError as error:
        judgment.need(reason in str(error),'ACCEPTANCE_WRONG_REJECTION:'+str(error))
        return str(error)
    raise judgment.Blocked('ACCEPTANCE_UNEXPECTED_ACCEPTANCE:'+reason)


def point8(inv,policy,docs,packet,spec,backend,offers,contexts):
    work=policy['work'];rule=planning.ENGINE_RULE;binding=packet['binding'];cases=[]
    def judge(inventory=inv, current=contexts, offer=offers, previous=None):
        return judgment.judge(inventory,work,offer,backend,current_contexts=current,previous_contexts=previous)
    def record(name, detail, scope):
        cases.append({'case':name,'test_passed':True,'detail':detail,'scope':scope,
                      'asset_pass':False,'advancement_authorized':False})
    # Exact structural failure reasons prevent unrelated existing blockers from
    # making the omission tests vacuously pass.
    altered=copy.deepcopy(inv);altered['families'].pop(next(iter(altered['families'])))
    reason=expected_rejection(lambda:judge(altered),'JUDGMENT_INVENTORY_INCOMPLETE')
    record('missing_family',reason,'ADVERSE_REQUEST_REAL_CANONICAL_INVENTORY')
    altered=copy.deepcopy(inv);family=next(iter(altered['families']));altered['families'][family].pop()
    reason=expected_rejection(lambda:judge(altered),'JUDGMENT_INVENTORY_INCOMPLETE')
    record('missing_rule',reason,'ADVERSE_REQUEST_REAL_CANONICAL_INVENTORY')
    altered=copy.deepcopy(packet);altered.pop('mg0')
    reason=expected_rejection(lambda:judgment.semantic_packet(altered,binding,spec),'JUDGMENT_RULE_PACKET')
    record('missing_individual_mg0',reason,'IN_MEMORY_TAMPER_TEST_OF_ACTUAL_NATIVE_PACKET')
    value=backend.rule(rule,binding,None)
    judgment.need(value.get('reason')=='NATIVE_RULE_PROOF_MISSING','ACCEPTANCE_MISSING_PROOF')
    record('missing_proof',value,'ADVERSE_REQUEST_TO_NATIVE_RULE_BACKEND')
    # Compute a real negative predicate against real source contents with an
    # intentionally inconsistent target expectation. Never publish it as a new
    # genuine work verdict or a native issuer result.
    wrong_policy=copy.deepcopy(policy['engine'])
    wrong_policy['canonical_target_line']='C08 intentionally inconsistent destination expectation'
    negative,_=planning.documented_engine(inv,work,docs,wrong_policy)
    verdict=judgment.semantic_packet(negative,binding,spec)
    judgment.need(negative['rule']['result']=='FAIL' and verdict['result']=='FAIL','ACCEPTANCE_FAIL_NOT_STOPPED')
    record('explicit_fail',{'computed_predicate':'FAIL','consumer_result':verdict['result']},
           'ALTERED_EXPECTATION_TEST_USING_REAL_SOURCE_CONTENTS')
    changed=copy.deepcopy(contexts);dep=next(iter(work['work_dependencies']))
    changed['rescue']['dependencies'][dep]='0'*64
    changed['rescue']['state']['version']+=1
    changed['rescue']['state']['sha256']=judgment.digest('C08 altered relevant context')
    changed['rescue']['observed_at']=(datetime.fromisoformat(changed['rescue']['observed_at'])+timedelta(seconds=1)).isoformat()
    changed['rescue']['observation_id']=judgment.context.digest({k:v for k,v in changed['rescue'].items() if k!='observation_id'})
    changed_result=judge(current=changed,previous=contexts)
    judgment.need('CURRENT_WORK_DEPENDENCY_CHANGED:rescue' in changed_result['blockers'] and
                  changed_result['action']=='STOP_CONTEXT_RECHECK','ACCEPTANCE_RELEVANT_CONTEXT_NOT_STOPPED')
    record('relevant_context_changed',changed_result['blockers'],'ADVERSE_CONTEXT_TEST_USING_REAL_RECEIPT')
    # Actually retrieve native Git proof for a mismatched attempt; do not use a
    # fake Git API or mutate the remote issuer output.
    backend.cache.clear();wrong=copy.deepcopy(binding);wrong['attempt_id']='0'*64
    denied=backend.rule(rule,wrong,offers[rule])
    judgment.need(denied['result']=='UNKNOWN' and 'REPLAY_OR_CONTEXT' in denied.get('reason',''),
                  'ACCEPTANCE_OLD_ATTEMPT_ACCEPTED')
    record('old_evidence_other_attempt',denied,'LIVE_NATIVE_GIT_READBACK_WRONG_ATTEMPT')
    backend.cache.clear();recovered=backend.rule(rule,binding,offers[rule])
    judgment.need(recovered.get('proof_digest')==judgment.digest(packet) and
                  recovered.get('semantic_scope')==judgment.SEMANTIC_SCOPE and recovered.get('mg0')=='UNKNOWN',
                  'ACCEPTANCE_CORRECTED_RETRIEVAL_FAILED')
    record('corrected_native_request',{'native_contents_authenticated':True,'individual_mg0':'UNKNOWN',
           'overall_rule':'UNKNOWN','eligible_work_advance':False},'LIVE_NATIVE_TRANSPORT_RECOVERY_ONLY')
    unrelated=copy.deepcopy(contexts);unrelated['rescue']['dependencies'][judgment.digest('C08 unrelated')]='1'*64
    unrelated['rescue']['state']['version']+=1
    unrelated['rescue']['state']['sha256']=judgment.digest('C08 unrelated update')
    unrelated['rescue']['observed_at']=(datetime.fromisoformat(unrelated['rescue']['observed_at'])+timedelta(seconds=1)).isoformat()
    unrelated['rescue']['observation_id']=judgment.context.digest({k:v for k,v in unrelated['rescue'].items() if k!='observation_id'})
    baseline=judge();other=judge(current=unrelated,previous=contexts)
    judgment.need(other['blockers']==baseline['blockers'] and other['counts']==baseline['counts'],
                  'ACCEPTANCE_UNRELATED_UPDATE_RESTARTED_WORK')
    record('unrelated_context_no_added_block',{'same_blockers':True,'same_counts':True},
           'ADVERSE_CONTEXT_TEST_USING_REAL_RECEIPT')
    return {'schema':'gg-c08-acceptance-v1','status':'PARTIAL_NEGATIVE_GATES_AND_NATIVE_TRANSPORT_RECOVERY_VERIFIED',
            'cases':cases,'tests_passed':len(cases),'family_count':inv['family_count'],'rule_count':inv['rule_count'],
            'eligible_work_correction_proven':False,'remaining':'Actual eligible corrected work advance requires C07 semantics/MG0',
            'c07_left_open_by_owner':True,'actual_asset_passes':0,'advancement_authorized':False}


def point9(inv,policy,backend,offers,contexts):
    logs=judgment.evidence.native(backend.api,DECISION,DECISION_ISSUER,
                                 'Verify native planning evidence and retain all canonical rules')
    native=one_packet(logs,'C07_NATIVE_PROCESS_JUDGMENT:')
    backend.cache.clear()
    fresh=judgment.judge(inv,policy['work'],offers,backend,current_contexts=contexts)
    judgment.need(native==fresh,'ACCEPTANCE_C09_NATIVE_DECISION_CHANGED')
    used=set()
    reason=expected_rejection(lambda:judgment._consume_checked(native,fresh,policy['work'],
                              policy['work']['operation_sha256'],used),'JUDGMENT_ADVANCEMENT_DENIED')
    judgment.need(not used,'ACCEPTANCE_C09_DENIED_OPERATION_CONSUMED')
    return {'schema':'gg-c09-readiness-v1','status':'BLOCKED_AT_PREREQUISITES_NO_COMPLETE_OPERATIONAL_CYCLE',
            'gate_denial':reason,'family_count':fresh['family_count'],'rule_count':fresh['rule_count'],
            'counts':fresh['counts'],'blockers':fresh['blockers'],
            'native_decision_origin':DECISION,'native_decision_authenticated':True,
            'scope':'READINESS_AND_LOW_LEVEL_CONSUMPTION_DENIAL_NOT_CONTROLLER_EXECUTION_OR_ASSET_CYCLE',
            'work_mode':policy['work']['mode'],'controlled_asset_cycle_started':False,
            'actual_asset_passes':0,'advancement_authorized':False,'c07_left_open_by_owner':True}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--point',choices=('8','9'),required=True)
    parser.add_argument('--ref',required=True);parser.add_argument('--master-sha',required=True)
    args=parser.parse_args(argv)
    try:
        judgment.need(re.fullmatch('[a-f0-9]{40}',args.ref),'ACCEPTANCE_IMMUTABLE_REF')
        api=OriginAPI(os.environ['GH_REVIEW_TOKEN'],os.environ['GITHUB_REPOSITORY'])
        judgment.need(planning.sha(api.repository.encode())==PRIVATE_REPO_SHA,'ACCEPTANCE_REPOSITORY')
        inv,policy,docs,packet,spec,backend,offers,contexts=load_case(api,args.ref,args.master_sha)
        result=point8(inv,policy,docs,packet,spec,backend,offers,contexts) if args.point=='8' else point9(inv,policy,backend,offers,contexts)
        print('C0'+args.point+'_NATIVE_ACCEPTANCE:'+json.dumps(result,sort_keys=True))
        return 0
    except (ValueError,KeyError,TypeError,OSError) as exc:
        print('ACCEPTANCE_TEST_EXECUTION_ERROR:'+str(exc));return 1


if __name__=='__main__':raise SystemExit(main())
