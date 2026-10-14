"""Source-bound, per-ID documentary semantics for the *actual* R173 QA reports.

Tests only the stated P0 documentation predicates, not the quality of the model.
The returned per-rule MG0 is UNKNOWN; a documentary predicate is never the
complete process verdict. The same validator can emit schema-correct packets
for an actual Controller-bound work request, without inventing one.
"""
import argparse
import copy
import hashlib
import json
import os
import re

import family_coverage as f
import supervisor_judgment as j
from qa_transport_r173 import validate as verify_qa, PACKET_SHA, MASTER_SHA

CATALOG_SHA='f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9'
RULES={
 'AAA-200-A-008':(8,'Riconoscere la differenza tra un fatto verificato e una supposizione.'),
 'AAA-200-A-009':(9,'Non dichiarare mai completato ciò che non è stato verificato.'),
 'AAA-200-B-011':(11,'Identificare lo scopo esatto dell’asset o dell’ambiente.'),
 'AAA-200-B-015':(15,'Separare gli elementi approvati da quelli ancora modificabili.'),
 'AAA-200-B-016':(16,'Identificare le dipendenze tra modelli, terreno, vegetazione e architettura.'),
 'AAA-200-B-017':(17,'Definire cosa deve essere realmente consegnato, non soltanto studiato.'),
 'AAA-200-B-018':(18,'Individuare i rischi tecnici prima di iniziare la produzione.'),
}
VALIDATOR='GG_R173_DOCUMENTARY_P0_7_RULES_V2'
LABEL='C07_R173_SOURCE_BOUND_RULE_CRITERIA:'

def require(cond,reason):
    if not cond:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def inspect(packet_raw,catalog_raw):
    # Both raw byte streams are immutable, source-pinned inputs to the verifier.
    proof=verify_qa(packet_raw)
    require(sha(catalog_raw)==CATALOG_SHA,'R173_RULE_CANONICAL_CATALOG_DRIFT')
    cat=json.loads(catalog_raw)
    require(cat.get('schema')=='GG_AAA200_CATALOG_V1','R173_RULE_CATALOG_SCHEMA')
    lines={item['id']:item for item in cat['catalog']}
    for rid,(number,required) in RULES.items():
        entry=lines[number]
        require(entry['id']==number and entry['requirement']==required and
                entry['phase']=='P0' and entry['asset_type']=='all',
                'R173_RULE_CANONICAL_ID_REQUIREMENT_DRIFT:'+rid)
    packet=json.loads(packet_raw)
    reports={name:json.loads(item['raw_text']) for name,item in packet['reports'].items()}
    bank=reports['R173_BANK_DESIGN_AND_INTEGRATION_QA.json']
    source=reports['R173_SOURCE_GEOMETRY_QA.json']
    road=reports['R173_ROAD_VOLUME_AND_PREVIEW_LODS_QA.json']
    context=reports['R173_R98_SCHEMATIC_CONTEXT_QA.json']
    checks={
     'AAA-200-A-008':{
       'uncertain_walkability_explicit':bank['bridge_deck_walkability']=='UNKNOWN' and source['collision_walkability']=='UNKNOWN',
       'unknown_world_water_z_explicit':bank['water_final_level_gta_z']=='UNKNOWN_NO_PLANE_EXPORTED' and source['water_final_Z']=='UNKNOWN',
       'artistic_result_not_assumed':source['status']=='ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM' and bank['artist_approval']=='PENDING',
       'reliability_scope_limited':proof['binary_asset_contents_read_by_git'] is False and proof['advancement_authorized'] is False},
     'AAA-200-A-009':{
       'r173_not_claimed_final':source['status']=='ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM',
       'scope_not_misrepresented_as_production':bank['stage']=='DESIGN_REVIEW_NOT_PRODUCTION',
       'owner_approval_not_forged':bank['artist_approval']=='PENDING',
       'runtime_collision_not_declared_pass':road['slope_collision_artistic']=='NOT_ACCEPTED',
       'independent_binary_not_falsely_claimed':proof['binary_asset_contents_read_by_git'] is False},
     'AAA-200-B-011':{
       'actual_path_scope_counted':type(source['new_route_count']) is int and source['new_route_count']>0,
       'real_path_extent_documented':type(source['total_length_m']) in (float,int) and source['total_length_m']>0,
       'path_review_not_final_asset':source['status']=='ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM',
       'bank_rework_purpose_explicit':bank['stage']=='DESIGN_REVIEW_NOT_PRODUCTION'},
     'AAA-200-B-015':{
       'protected_r98_explicitly_not_modified':bank['R98_source_changed'] is False and
           'source R98 untouched' in source['gate_source_copy'],
       'rejected_r170_r171_excluded':source['explicitly_rejected_assets']=='R170_R171 environment intentionally excluded',
       'r173_pending_not_accepted':bank['artist_approval']=='PENDING' and
           source['status']=='ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM',
       'golden_market_not_integrated':context['market']=='BLEND NOT INCLUDED -- FOOTPRINT REFERENCE ONLY'},
     'AAA-200-B-016':{
       'landing_dependencies_named':len(source['bridge_landings_pending'])==8 and
            len({x['name'] for x in source['bridge_landings_pending']})==8 and
            all(x.get('reason') and x.get('start') and x.get('target')
                for x in source['bridge_landings_pending']),
       'terrain_design_not_world_surface':source['terrain']=='R101 DESIGN EVIDENCE ONLY, not complete mesh terrain' and
            source['R101_world_position']=='local datum NOT GTA absolute origin',
       'water_and_collision_unknown':source['water_final_Z']=='UNKNOWN' and
            source['collision_walkability']=='UNKNOWN',
       'r98_dependency_preserved':bank['R98_source_changed'] is False},
     'AAA-200-B-017':{
       'review_candidate_scope_explicit':source['status']=='ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM',
       'geometry_export_not_signed_off':source['export_GLB_render']=='UNVERIFIED_PENDING_INDEPENDENT_REIMPORT',
       'owner_delivery_acceptance_pending':bank['artist_approval']=='PENDING' and
             context['acceptance']=='NONE',
       'final_fivem_runtime_not_claimed':road['status']=='GEOMETRY_PREVIEW_COLLISION_VOLUMES_NOT_FIVEM_CONVERTED'},
     'AAA-200-B-018':{
       'prior_block_named':bank['AAA200']=='R172_BLOCKED_NOT_PROMOTED',
       'eight_landing_risks_documented':len(source['bridge_landings_pending'])==8 and all(x['reason'] for x in source['bridge_landings_pending']),
       'grade_risk_quantified':source['max_centerline_designed_grade']>0.13 and source['slope_over_5percent_total_m']>100,
       'water_collision_risks_unresolved':source['water_final_Z']=='UNKNOWN' and source['collision_walkability']=='UNKNOWN' and road['slope_collision_artistic']=='NOT_ACCEPTED',
       'prior_approved_source_intact':bank['R98_source_changed'] is False}
    }
    results={}
    for rid,rule_checks in checks.items():
        result='PASS' if all(rule_checks.values()) else 'FAIL'
        results[rid]={
            'canonical_requirement':RULES[rid][1],
            'catalog_requirement_sha256':sha(RULES[rid][1].encode()),
            'documentary_checks':rule_checks,
            'documentary_result':result,
            'individual_rule_mg0':'UNKNOWN',
            'proof_digest':j.digest({'rule_id':rid,'report_content_sha256':PACKET_SHA,
                                    'catalog_sha256':CATALOG_SHA,'criteria':rule_checks})}
    return {'schema':'gg-r173-p0-documentary-verdict-v1',
            'validator_id':VALIDATOR,'canonical_master_sha256':MASTER_SHA,
            'packet_sha256':PACKET_SHA,'catalog_sha256':CATALOG_SHA,
            'rule_count':len(results),'results':results,
            'verified':proof['qa_metadata_contents_and_consistency']=='PASS',
            'individual_rule_mg0_passes':0,'asset_execution_verified':False,
            'advancement_authorized':False,'scope':'R173_P0_DOCUMENTARY_FACTS_ONLY'}

def packets_for_current_work(report,work,inventory):
    """Emit individual native semantic packets ONLY for provided current work.

    No default synthetic work item or invented Controller enrollment is allowed.
    A verified documentation predicate does not excuse individual MG0.
    """
    j.validate_work(work,inventory)
    require(work['master_sha256']==MASTER_SHA and work['phase']=='P0' and
            work['asset_type']=='terrain' and
            work['mode'] in ('DIAGNOSTIC_ONLY','OPERATIONAL'),
            'R173_RULE_ACTUAL_WORK_SCOPE')
    packets={}
    for rid,detail in report['results'].items():
        row=inventory['rules'][rid]
        require(row['requirement']==detail['canonical_requirement'] and
                row['requirement_sha256']==detail['catalog_requirement_sha256'],
                'R173_RULE_SOURCE_REQUIREMENT_BINDING:'+rid)
        bound=j.binding(work,row,rid)
        packet={'schema':'gg-semantic-rule-v1','scope':j.SEMANTIC_SCOPE,
                'validator_id':VALIDATOR,'binding':bound,
                'rule':{'result':detail['documentary_result'],
                        'checks':detail['documentary_checks'],
                        'proof_digest':detail['proof_digest']},
                'mg0':{'binding':copy.deepcopy(bound),'triggered':None,'result':'UNKNOWN',
                       'checks':{'canonical_triggers_checked':False},
                       'proof_digest':j.digest({'id':rid,'status':'INDIVIDUAL_MG0_UNVERIFIED',
                                                'packet':PACKET_SHA})}}
        spec={'validator_id':VALIDATOR,'criteria':list(detail['documentary_checks'])}
        computed=j.semantic_packet(packet,bound,spec)
        require(computed['result']=='UNKNOWN','R173_RULE_FALSE_OVERALL_PASS')
        packets[rid]=packet
    return packets

def native_rule_readback(api, packet, expected, enrolled_spec):
    """Independent consuming-side rule proof validation, not producer PASS trust.

    Fetch the *exact* source-approved evidence bytes on immutable private Git
    and re-run all of the per-rule criteria before honoring any native packet.
    The documentary check may PASS; individual MG0 MUST remain UNKNOWN.
    """
    from broker_live_review import decode_file
    source_ref=enrolled_spec.get('source_ref')
    require(isinstance(source_ref,str) and re.fullmatch(r'[0-9a-f]{40}',source_ref),
            'R173_RULE_NATIVE_IMMUTABLE_SOURCE_REF')
    rid=expected.get('rule_id')
    require(rid in RULES and expected.get('phase')=='P0' and
            expected.get('family')=='AAA-200' and
            expected.get('master_sha256')==MASTER_SHA and
            expected.get('source_sha256')==CATALOG_SHA and
            expected.get('requirement_sha256')==sha(RULES[rid][1].encode()),
            'R173_RULE_NATIVE_CANONICAL_BINDING')
    require(enrolled_spec.get('validator_id')==VALIDATOR,
            'R173_RULE_NATIVE_VALIDATOR_ID')
    raw={}
    for key,path in [('qa','governance/supervisor/evidence/r173/GG_R173_QA_METADATA_ONLY_PROOF.json'),
                     ('catalog','governance/sources/AAA_200_CANONICAL_CATALOG.json')]:
        raw[key]=decode_file(api.call('GET','/contents/'+path+'?ref='+source_ref),path)
    verified=inspect(raw['qa'],raw['catalog'])
    item=verified['results'][rid]
    require(set(enrolled_spec.get('criteria',()))==set(item['documentary_checks']),
            'R173_RULE_NATIVE_CRITERIA_REQUIRED')
    require(packet.get('rule')=={
       'result':item['documentary_result'],
       'checks':item['documentary_checks'],
       'proof_digest':item['proof_digest']},
       'R173_RULE_NATIVE_CONTENT_OR_RESULT_MISMATCH')
    require(packet.get('mg0')=={
       'binding':expected,'triggered':None,'result':'UNKNOWN',
       'checks':{'canonical_triggers_checked':False},
       'proof_digest':j.digest({'id':rid,'status':'INDIVIDUAL_MG0_UNVERIFIED',
                                 'packet':PACKET_SHA})},
       'R173_RULE_NATIVE_FALSE_MG0')
    return {'rule_id':rid,'documentary_result':item['documentary_result'],
            'individual_rule_mg0':'UNKNOWN','asset_advancement_authorized':False}

def main(argv=None):
    from broker_live_review import decode_file
    from git_judgment_origin import OriginAPI,PRIVATE_REPO_SHA
    p=argparse.ArgumentParser()
    p.add_argument('--ref',required=True)
    args=p.parse_args(argv)
    try:
        require(re.fullmatch(r'[0-9a-f]{40}',args.ref) is not None,'R173_RULE_IMMUTABLE_REF')
        api=OriginAPI(os.environ['GH_REVIEW_TOKEN'],os.environ['GITHUB_REPOSITORY'])
        require(sha(api.repository.encode())==PRIVATE_REPO_SHA,'R173_RULE_REPOSITORY')
        docs={}
        for key,path in [('qa','governance/supervisor/evidence/r173/GG_R173_QA_METADATA_ONLY_PROOF.json'),
                         ('catalog','governance/sources/AAA_200_CANONICAL_CATALOG.json')]:
            docs[key]=decode_file(api.call('GET','/contents/'+path+'?ref='+args.ref),path)
        print(LABEL+json.dumps(inspect(docs['qa'],docs['catalog']),sort_keys=True))
        return 0
    except (ValueError,TypeError,KeyError,OSError) as exc:
        print('R173_RULE_VERIFICATION_BLOCKED:'+str(exc))
        return 1
if __name__=='__main__':raise SystemExit(main())
