"""Full-inventory process judgment. Authentic linkage is never semantic PASS.

NativeRuleBackend accepts only scoped, enrolled per-rule validators. The initial
installation has no asset-rule validator enrolled; unsupported rules are UNKNOWN.
"""
import copy
import hashlib
import json
import re
import family_coverage as coverage
import supervisor_context as context
import rule_evidence as evidence

SEMANTIC_SCOPE='PER_RULE_PROCESS_VERDICT'
PREFIX='C07_SEMANTIC_RULE_VERDICT:'
SEMANTIC_STEP='Validate canonical rule and individual MG0 semantics'
class Blocked(ValueError):pass
def need(v,r):
    if not v:raise Blocked(r)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def binding(work,row,rule):
    return {'work_item_sha256':work['work_item_sha256'],'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
            'attempt_number':work['attempt_number'],'previous_attempt_id':work['previous_attempt_id'],
            'phase':work['phase'],'family':row['family'],'rule_id':rule,
            'master_sha256':work['master_sha256'],'source_sha256':row['source_sha256'],
            'requirement_sha256':row['requirement_sha256'],
            'work_dependencies':work['work_dependencies']}
def validate_work(work,inv):
    keys={'work_item_sha256','attempt_id','operation_sha256','attempt_number','previous_attempt_id','phase','asset_type','profiles','master_sha256','work_dependencies','asset_specific_extensions_verified','guardian_required','mode','closure_requested'}
    need(isinstance(work,dict) and set(work)==keys,'JUDGMENT_WORK_SCHEMA')
    for k in ('work_item_sha256','attempt_id','operation_sha256','master_sha256'):need(evidence.is_sha(work[k]),'JUDGMENT_WORK_DIGEST')
    need(work['master_sha256']==inv['canonical_master_sha256'],'JUDGMENT_MASTER')
    need(type(work['attempt_number']) is int and work['attempt_number']>0,'JUDGMENT_ATTEMPT')
    need((work['attempt_number']==1 and work['previous_attempt_id'] is None) or (work['attempt_number']>1 and evidence.is_sha(work['previous_attempt_id']) and work['previous_attempt_id']!=work['attempt_id']),'JUDGMENT_CORRECTION_LINK')
    need(work['phase'] in coverage.PHASES and work['asset_type'] in coverage.ASSET_TYPES,'JUDGMENT_PHASE_TYPE')
    known={r['profile'] for r in inv['rules'].values() if 'profile' in r}
    need(isinstance(work['profiles'],list) and work['profiles'] and len(work['profiles'])==len(set(work['profiles'])) and set(work['profiles'])<=known,'JUDGMENT_PROFILE')
    need(isinstance(work['work_dependencies'],dict) and work['work_dependencies'] and all(evidence.is_sha(k) and evidence.is_sha(h) for k,h in work['work_dependencies'].items()),'JUDGMENT_DEPENDENCIES')
    for k in ('asset_specific_extensions_verified','guardian_required','closure_requested'):need(type(work[k]) is bool,'JUDGMENT_WORK_POLICY')
    need(work['mode'] in ('OPERATIONAL','DIAGNOSTIC_ONLY'),'JUDGMENT_MODE')
def semantic_packet(packet,expected,spec):
    """Only called after native provenance verification, never on producer claims."""
    evidence.exact(packet,('schema','scope','validator_id','binding','rule','mg0'),'JUDGMENT_RULE_PACKET')
    need(packet['schema']=='gg-semantic-rule-v1' and packet['scope']==SEMANTIC_SCOPE and packet['validator_id']==spec['validator_id'],'JUDGMENT_SEMANTIC_SCOPE')
    need(packet['binding']==expected,'JUDGMENT_EVIDENCE_REPLAY_OR_CONTEXT')
    rule=packet['rule'];mg=packet['mg0'];evidence.exact(rule,('result','checks','proof_digest'),'JUDGMENT_RULE_CHECKS');evidence.exact(mg,('binding','triggered','result','checks','proof_digest'),'JUDGMENT_MG0')
    need(rule['result'] in ('PASS','FAIL','UNKNOWN') and isinstance(rule['checks'],dict) and set(rule['checks'])==set(spec['criteria']),'JUDGMENT_CRITERIA_COVERAGE')
    need(evidence.is_sha(rule['proof_digest']) and (type(mg['triggered']) is bool or mg['triggered'] is None) and mg['binding']==expected and mg['result'] in ('PASS','FAIL','UNKNOWN'),'JUDGMENT_MG0_BINDING')
    # UNKNOWN trigger state is distinct from a proved canonical trigger. In that
    # case no correction loop is invented and a PASS is categorically forbidden.
    if mg['triggered'] is None:
        need(mg['result']=='UNKNOWN','JUDGMENT_MG0_UNRESOLVED_TRIGGER_CANNOT_PASS')
    needed=('cause_identified','affected_states_invalidated','correction_applied','reapplied_on_current_attempt') if mg['triggered'] is True else ('canonical_triggers_checked',)
    need(isinstance(mg['checks'],dict) and set(mg['checks'])==set(needed) and evidence.is_sha(mg['proof_digest']),'JUDGMENT_MG0_REQUIRED_CHECKS')
    for checks in (rule['checks'],mg['checks']):need(all(type(v) is bool for v in checks.values()),'JUDGMENT_NONBOOLEAN_CHECK')
    if rule['result']=='FAIL' or mg['result']=='FAIL':result='FAIL'
    elif rule['result']=='UNKNOWN' or mg['result']=='UNKNOWN':result='UNKNOWN'
    elif not all(rule['checks'].values()) or not all(mg['checks'].values()):result='FAIL'
    else:result='PASS'
    return {'result':result,'mg0':mg['result'],'semantic_scope':SEMANTIC_SCOPE,'proof_digest':digest(packet)}
class NativeRuleBackend:
    synthetic=False
    def __init__(self,api,enrolled):self.api=api;self.enrolled=enrolled;self.cache={}
    def rule(self,rule,expected,offer):
        spec=self.enrolled.get(rule)
        if spec is None:return {'result':'UNKNOWN','reason':'NO_ENROLLED_RULE_SEMANTIC_VALIDATOR'}
        need(spec['requirement_sha256']==expected['requirement_sha256'] and spec['criteria'],'JUDGMENT_VALIDATOR_SOURCE_DRIFT')
        if not isinstance(offer,dict) or set(offer)!=set(('native_origin','expected_packet_sha256')):return {'result':'UNKNOWN','reason':'NATIVE_RULE_PROOF_MISSING'}
        key=(digest(offer['native_origin']),digest(spec['issuer']))
        try:
            if key not in self.cache:
                logs=evidence.native(self.api,offer['native_origin'],spec['issuer'],SEMANTIC_STEP)
                values=[]
                for line in logs.splitlines():
                    m=re.fullmatch(r'\d{4}-\d\d-\d\dT\S+Z '+re.escape(PREFIX)+r'(\{.*\})',line)
                    if m:values.append(evidence.strict_json(m.group(1).encode(),max_size=65536))
                self.cache[key]=values
            packets=[p for p in self.cache[key] if p.get('binding',{}).get('rule_id')==rule]
            need(len(packets)==1,'JUDGMENT_NATIVE_RULE_UNIQUE');packet=packets[0]
            need(digest(packet)==offer['expected_packet_sha256'],'JUDGMENT_NATIVE_PACKET_DIGEST')
            if spec['validator_id'] == 'GG_R173_DOCUMENTARY_P0_A008_B018_V1':
                # Independent readback of content/criteria from the exact R173
                # pinned sources. A native PASS tag or 64-char digest is not proof.
                from r173_rule_semantics import native_rule_readback
                native_rule_readback(self.api,packet,expected,spec)
            return semantic_packet(packet,expected,spec)
        except (ValueError,KeyError,TypeError) as exc:return {'result':'UNKNOWN','reason':str(exc)}
def judge(inv,work,offers,backend,*,current_contexts,previous_contexts=None,previous_decision=None):
    """work and enrolled validators are trusted consumer inputs, not PR waivers.

    This preserves ALL IDs, including future/N_A; N_A is not a work PASS.
    C04 applicability defaults are retained conservatively. Missing asset-specific
    extensions prohibit authorization until canonical extensions are reconciled.
    """
    validate_work(work,inv);need(isinstance(offers,dict),'JUDGMENT_OFFERS')
    flattened=[r for group in inv['families'].values() for r in group]
    need(flattened and len(flattened)==len(set(flattened)) and set(flattened)==set(inv['rules']),'JUDGMENT_INVENTORY_INCOMPLETE')
    ids=set(inv['rules']);extras=set(offers)-ids;need(not extras,'JUDGMENT_UNKNOWN_RULE_IDS')
    need(isinstance(current_contexts,dict) and set(current_contexts)=={'rescue','guardian'},'JUDGMENT_CONTEXTS')
    blockers=[];context_changes=[]
    for role,v in current_contexts.items():
        context.validate(v);need(v['role']==role,'JUDGMENT_CONTEXT_ROLE')
        r=context.assess((previous_contexts or {}).get(role),v,list(work['work_dependencies']),work['guardian_required'])
        if v['master']['sha256']!=work['master_sha256']:blockers.append('CURRENT_MASTER_CHANGED')
        if any(v['dependencies'].get(k)!=h for k,h in work['work_dependencies'].items()):blockers.append('CURRENT_WORK_DEPENDENCY_CHANGED:'+role)
        if r['action'] in ('STOP_RELEVANT_CONTEXT_UNKNOWN','RECHECK_AFFECTED_CONTROLS'):
            blockers.append(r['action']+':'+role);context_changes.append(r)
    if not work['asset_specific_extensions_verified']:blockers.append('ASSET_SPECIFIC_EXTENSIONS_UNVERIFIED')
    if work['attempt_number']>1:
        if not previous_decision or previous_decision.get('work_item_sha256')!=work['work_item_sha256'] or previous_decision.get('attempt_id')!=work['previous_attempt_id'] or previous_decision.get('attempt_number')!=work['attempt_number']-1 or previous_decision.get('action') not in ('STOP_CORRECT_RESUBMIT','STOP_CONTEXT_RECHECK'):
            blockers.append('PREVIOUS_FAILED_ATTEMPT_NOT_VERIFIED')
    results={};counts={'PASS':0,'FAIL':0,'UNKNOWN':0,'FUTURE_PHASE':0,'N_A':0}
    for family,rules in inv['families'].items():
        family_results={}
        for rule in rules:
            row=inv['rules'][rule];wanted=coverage.expected_result(row,work['phase'],work['asset_type'],work['profiles'])
            expected=binding(work,row,rule)
            # Applicability is derived from the immutable canonical source and
            # the Controller-enrolled work context, never an executor's waiver.
            # All IDs remain visible. No future/N_A ID is called a PASS or MG0 PASS.
            if wanted != 'PASS':
                if wanted == 'FUTURE_PHASE':
                    need(row.get('catalog_phase') in coverage.PRO_PHASES,
                         'JUDGMENT_FUTURE_WITHOUT_CANONICAL_PHASE')
                elif wanted == 'N_A_ASSET_TYPE':
                    need(row.get('asset_type') not in (None, 'all', work['asset_type']),
                         'JUDGMENT_NA_WITHOUT_CANONICAL_ASSET_TYPE')
                elif wanted == 'N_A_PROFILE_NOT_SELECTED':
                    need(row.get('profile') is not None and row['profile'] not in work['profiles'],
                         'JUDGMENT_NA_WITHOUT_CANONICAL_PROFILE')
                else:
                    raise Blocked('JUDGMENT_UNSUPPORTED_APPLICABILITY:'+str(wanted))
                basis={'rule_id':rule, 'binding':expected, 'applicability':wanted,
                       'work_phase':work['phase'], 'asset_type':work['asset_type'],
                       'profiles':work['profiles'], 'canonical_phase':row.get('catalog_phase'),
                       'canonical_asset_type':row.get('asset_type'),
                       'canonical_profile':row.get('profile')}
                status='FUTURE_PHASE' if wanted=='FUTURE_PHASE' else 'N_A'
                counts[status]+=1
                family_results[rule]={'result':status,'expected_applicability':wanted,
                                      'mg0':'NOT_DUE_NO_CURRENT_RULE_PASS',
                                      'evidence_digest':digest(basis),
                                      'reason':'SOURCE_AND_TRUSTED_WORK_CONTEXT_APPLICABILITY',
                                      'binding_sha256':digest(expected),
                                      'applicability_basis':basis}
                continue
            try:r=backend.rule(rule,expected,offers.get(rule))
            except (ValueError,KeyError,TypeError) as exc:r={'result':'UNKNOWN','reason':str(exc)}
            need(isinstance(r,dict) and r.get('result') in ('PASS','FAIL','UNKNOWN'),'JUDGMENT_BACKEND_RESULT')
            status=r['result']
            if status=='PASS':
                need(r.get('mg0')=='PASS' and r.get('semantic_scope')==SEMANTIC_SCOPE and evidence.is_sha(r.get('proof_digest')),'JUDGMENT_NOT_A_SEMANTIC_MG0_PASS')
            counts[status]+=1
            family_results[rule]={'result':status,'expected_applicability':wanted,'mg0':r.get('mg0','UNKNOWN'),'evidence_digest':r.get('proof_digest'),'reason':r.get('reason'),'binding_sha256':digest(expected)}
        results[family]=family_results
    if counts['FAIL'] or counts['UNKNOWN']:blockers.append('REQUIRED_RULE_OR_MG0_NOT_VERIFIED')
    if not counts['PASS']:blockers.append('NO_APPLICABLE_RULE_SEMANTIC_PASS')
    if work['closure_requested'] and (counts['FUTURE_PHASE'] or work['phase']!='DELIVERY'):blockers.append('FULL_CLOSURE_NOT_READY')
    ready=not blockers
    if any('CONTEXT' in x or 'DEPENDENCY' in x or 'MASTER_CHANGED' in x for x in blockers):action='STOP_CONTEXT_RECHECK'
    else:action='READY_FOR_EXACT_OPERATION' if ready else 'STOP_CORRECT_RESUBMIT'
    result={'schema':'gg-process-judgment-v1','work_item_sha256':work['work_item_sha256'],'attempt_id':work['attempt_id'],'attempt_number':work['attempt_number'],'phase':work['phase'],'master_sha256':work['master_sha256'],'work_dependencies':work['work_dependencies'],'action':action,'blockers':sorted(set(blockers)),'counts':counts,'family_count':len(results),'rule_count':sum(len(v) for v in results.values()),'families':results,'context_changes':context_changes,'phase_ready':ready,'closure_ready':ready and work['closure_requested'],'synthetic_backend':bool(backend.synthetic),'mode':work['mode'],'advancement_authorized':ready and not backend.synthetic and work['mode']=='OPERATIONAL','asset_execution_passes':0}
    result['decision_sha256']=digest(result)
    result['operation_sha256']=work['operation_sha256']
    result['decision_sha256']=digest({k:v for k,v in result.items() if k!='decision_sha256'})
    return result
def _consume_checked(decision,fresh,work,operation_id,used):
    need(isinstance(used,set) and evidence.is_sha(operation_id),'JUDGMENT_OPERATION_ID')
    need(operation_id not in used,'JUDGMENT_OPERATION_REPLAY')
    need(operation_id==work['operation_sha256'],'JUDGMENT_WRONG_OPERATION')
    for d in (decision,fresh):
        need(isinstance(d,dict) and d.get('advancement_authorized') is True and d.get('synthetic_backend') is False and d.get('mode')=='OPERATIONAL','JUDGMENT_ADVANCEMENT_DENIED')
        need(d.get('decision_sha256')==digest({k:v for k,v in d.items() if k!='decision_sha256'}),'JUDGMENT_DECISION_DIGEST')
    need(decision['decision_sha256']==fresh['decision_sha256'],'JUDGMENT_FRESH_DECISION_CHANGED')
    for k in ('work_item_sha256','attempt_id','operation_sha256','attempt_number','phase','master_sha256','work_dependencies'):need(decision[k]==work[k],'JUDGMENT_OPERATION_BINDING')
    used.add(operation_id)
    return {'status':'EXACT_OPERATION_CONSUMED','operation_id':operation_id,'decision_sha256':decision['decision_sha256']}
def native_decision(api, origin, issuer):
    """Read one actual native decision; a local previous-decision dict is no authority."""
    logs=evidence.native(api,origin,issuer,'Judge all canonical families and individual MG0')
    values=[]
    for line in logs.splitlines():
        m=re.fullmatch(r'\d{4}-\d\d-\d\dT\S+Z C07_NATIVE_PROCESS_JUDGMENT:(\{.*\})',line)
        if m:values.append(evidence.strict_json(m.group(1).encode(),max_size=1000000))
    need(len(values)==1,'JUDGMENT_NATIVE_DECISION_UNIQUE')
    d=values[0]
    need(d.get('decision_sha256')==digest({k:v for k,v in d.items() if k!='decision_sha256'}),'JUDGMENT_DECISION_DIGEST')
    return d

def consume_native(api,origin,issuer,inv,work,offers,backend,current_contexts,operation_id,used,*,previous_contexts=None,previous_decision=None):
    """Operational entry: native decision retrieval AND fresh rule verification.

    used must be restored from the canonical append-only operation journal and
    persisted together with the governed action. This does not isolate writers.
    """
    need(type(backend) is NativeRuleBackend and backend.api is api,'JUDGMENT_TRUSTED_BACKEND_REQUIRED')
    decision=native_decision(api,origin,issuer)
    backend.cache.clear() # Never use the old log cache to authorize a new step.
    fresh=judge(inv,work,offers,backend,current_contexts=current_contexts,previous_contexts=previous_contexts,previous_decision=previous_decision)
    return _consume_checked(decision,fresh,work,operation_id,used)
