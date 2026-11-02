"""C07 AAA-200 P2: execute the COMPLETE 50-rule G/H/I/J/K closure batch.

A single caller supplies FOUR independent original Controller attempts, one
for each real asset type. Exactly 20 architecture and 10 each organic,
vegetation and terrain original rule clauses are independently replayed.
The other 150 asset-type combinations are NOT_DUE, never passed or mixed.
The result contains 50 concrete source observations and fifty explicit
certification blockers; original PNG/GLB/policy presence is never treated
as literal semantic fitness, real engine play, or individual MG0 certification.

No asset file is created, overwritten or persisted. This function is a pure
consumer of original source loaders and cannot authorize a production run.
"""
import hashlib
import json

from c07_p2_fifty_asset_type_domain import (
    inspect as inspect_type, IDS as IDS50, TEXT)
from c07_native_source_rule_replayers import (
    build_packet, FULL_LITERAL_REVIEWED, NATIVE_RULES)
from c07_positive_native_process import _original_attempt
from supervisor_judgment import digest

ASSET_TYPES=('architecture','organic','vegetation','terrain')
EXPECTED_DUE={'architecture':20,'organic':10,'vegetation':10,'terrain':10}
EXPECTED_TOTAL=50
REVIEW_CHANNELS={
    'architecture':(
        'independent_original_geometry_vs_reference_design_qa',
        'independent_original_structure_proportion_joint_qa'),
    'organic':(
        'independent_original_natural_reference_visual_qa',
        'independent_measured_original_material_erosion_contact_qa'),
    'vegetation':(
        'independent_original_botanical_silhouette_distribution_qa',
        'independent_original_alpha_lod_and_wind_runtime_qa'),
    'terrain':(
        'independent_original_survey_water_terrain_contact_qa',
        'independent_original_paths_bridges_stairs_scene_qa'),
}
ENGINE_RULE='AAA-200-J-100'
class P2FiftyClosureBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise P2FiftyClosureBlocked(reason)

def inspect(contexts):
    """Return all 50 original criteria, source deficits and FULL blockers.

    Source checks can be satisfied in synthetic tests, yet these are NOT
    independent owner, runtime, aesthetic, or individual MG0 approvals.
    """
    need(type(contexts) is dict and set(contexts)==set(ASSET_TYPES),
         'C07_P2_FIFTY_EXACT_FOUR_ASSET_TYPE_CONTEXTS_REQUIRED')
    need(len(IDS50)==EXPECTED_TOTAL and
         len(set(IDS50))==EXPECTED_TOTAL and
         set(REVIEW_CHANNELS)==set(ASSET_TYPES),
         'C07_P2_FIFTY_CATALOG_OR_QA_CHANNEL_DRIFT')
    results={}
    contexts_digest={}
    source_proof_count=source_missing_count=0
    for kind in ASSET_TYPES:
        ctx=contexts[kind]
        need(type(ctx) is dict and set(ctx)=={
             'inventory','plan','controller','asset','step',
             'work','source_loader'} and
             ctx['work'].get('asset_type')==kind and
             ctx['plan'].get('asset_type')==kind and
             callable(ctx['source_loader']),
             'C07_P2_FIFTY_WRONG_ASSET_OR_UNTRUSTED_CONTEXT:'+kind)
        inv,plan,ctl,asset,step,work,loader=(
             ctx[k] for k in ('inventory','plan','controller',
              'asset','step','work','source_loader'))
        scope=inspect_type(inv,plan,ctl,asset,step,work,
                           source_loader=loader)
        audit,tail,state,audit_sha=_original_attempt(
             inv,plan,ctl,asset,step,work)
        need(scope['asset_type']==kind and
             scope['actual_due_rules']==EXPECTED_DUE[kind] and
             scope['other_asset_type_rules']==50-EXPECTED_DUE[kind] and
             scope['named_domain_probes']==100 and
             scope['full_semantic_passes']==0 and
             scope['individual_mg0_passes']==0 and
             scope['advancement_authorized'] is False and
             scope['original_audit_sha256']==audit_sha and
             scope['original_audit_tail']==tail and
             all(type(x) is dict and
                 x['applicability']==('DUE' if
                   x['source_asset_type']==kind else 'N_A_ASSET_TYPE') and
                 x['advancement_authorized'] is False and
                 x['individual_mg0']==('UNKNOWN' if
                   x['source_asset_type']==kind else 'NOT_DUE')
                 for x in scope['rules'].values()),
             'C07_P2_FIFTY_ORIGINAL_AUDIT_OR_TYPE_SCOPE_CHANGED:'+kind)
        contexts_digest[kind]={
             'asset':asset,'step':step,
             'attempt_id':work['attempt_id'],
             'operation_sha256':work['operation_sha256'],
             'original_audit_sha256':audit_sha,
             'original_audit_tail':tail,
             'master_sha256':work['master_sha256']}
        for rid in IDS50:
            row=scope['rules'][rid]
            if row['applicability']!='DUE':
                need(row['original_native_domain_predicates']=={} and
                     row['full_rule_semantics']=='NOT_DUE',
                     'C07_P2_FIFTY_NA_NEVER_CONVERT_TO_PASS:'+rid)
                continue
            need(rid not in results and
                 rid not in FULL_LITERAL_REVIEWED and
                 rid in NATIVE_RULES and
                 NATIVE_RULES[rid][0]=='p2_fifty_asset_source',
                 'C07_P2_FIFTY_DUPLICATE_OR_PREMATURE_FULL:'+rid)
            packet=build_packet(ctx,rid)
            checks=packet['rule']['checks']
            need(type(checks) is dict and
                 checks==row['original_native_domain_predicates'] and
                 set(checks)==set(NATIVE_RULES[rid][1]) and
                 len(checks)==2 and
                 all(type(x) is bool for x in checks.values()) and
                 packet['rule']['result']=='UNKNOWN' and
                 packet['mg0']['result'] in ('UNKNOWN','FAIL') and
                 packet['binding']['attempt_id']==work['attempt_id'],
                 'C07_P2_FIFTY_ORIGINAL_NATIVE_REPLAY_OR_FALSE_PASS:'+rid)
            missed=tuple(x for x,v in checks.items() if not v)
            source_proof_count+=sum(checks.values())
            source_missing_count+=len(missed)
            channels=REVIEW_CHANNELS[kind]
            # The runtime wind clause has an additional mandatory game
            # verification even if a self-reported receipt exists.
            if rid==ENGINE_RULE:
                channels+=('independent_fivem_wind_engine_execution',)
            results[rid]={
               'catalog_number':int(rid[-3:]),
               'original_literal':TEXT[str(int(rid[-3:]))][0],
               'asset_type':kind,
               'asset':asset,
               'source_checks':checks,
               'missing_original_source_checks':missed,
               'source_observations_complete':not missed,
               'code_review_full':False,
               'full_rule_semantics':'UNKNOWN',
               'individual_mg0':'UNKNOWN',
               'independent_qa_missing':channels,
               'owner_approval':'UNVERIFIED',
               'fivem_runtime':'UNVERIFIED' if rid==ENGINE_RULE else 'NOT_PROVEN_IF_REQUIRED',
               'advancement_authorized':False,
               'original_source_proof_digest':packet['rule']['proof_digest'],
            }
    need(len(results)==EXPECTED_TOTAL and
         set(results)==set(IDS50) and
         sum(1 for r in results.values() if
             r['asset_type']=='architecture')==20 and
         sum(1 for r in results.values() if
             r['asset_type']!='architecture')==30 and
         source_proof_count+source_missing_count==100 and
         all(not r['code_review_full'] and
             r['full_rule_semantics']=='UNKNOWN' and
             r['individual_mg0']=='UNKNOWN' and
             r['advancement_authorized'] is False and
             len(r['independent_qa_missing'])>=2
             for r in results.values()),
         'C07_P2_FIFTY_NO_PARTIAL_CERTIFICATION_OR_OMISSION')
    payload={'schema':'gg-c07-p2-fifty-single-operation-closure-v1',
             'exact_original_rules_examined':EXPECTED_TOTAL,
             'independent_original_source_checks':100,
             'original_source_positive_checks':source_proof_count,
             'original_source_missing_checks':source_missing_count,
             'asset_types':dict((k,EXPECTED_DUE[k]) for k in ASSET_TYPES),
             'current_original_contexts':contexts_digest,
             'full_rule_certifications':0,
             'individual_mg0_passes':0,
             'independent_owner_approvals':0,
             'advancement_authorized':False,
             'rules':results}
    payload['recomputed_result_sha256']=digest(payload)
    return payload
