"""Read and independently cross-check admissible R173 QA metadata, never 3D assets.

The metadata packet has a Library-verified origin and immutable SHA. Git can
verify exact text contents and internal claims; it CANNOT verify withheld binary
GLB contents, player walkability, final grade, artistic quality or rule/MG0 PASS.
"""
import argparse
import hashlib
import json
import os
import re

PACKET_SHA = 'c5eb4e7dd260b5e46855c4d627e67cf196a8239da54fb6123dbc1620a832456c'
ARCHIVE_SHA = '50cb0a4588b3e99bae7c2420f2b269645e1b4f97197ab22781ce5d00e7859ed5'
MASTER_SHA = '5ba978ec0543d898b1f376b2d3528aa08a36a6b46be6e429abbbc1bef87fc116'
LIBRARY_ID = 'libfile_f1f598db82cc8191b940cbe02850ae7e'
REPORT_SHA = {
 'R173_BANK_DESIGN_AND_INTEGRATION_QA.json':'5a45f1129cd64d2ae72b2194bedf22df6b2ca4517076516311ad24962990b27d',
 'R173_R98_SCHEMATIC_CONTEXT_QA.json':'cff6d517b4ea69f8604610eb7703a12224d71ad66b7bb04767ea356b8ec3f846',
 'R173_ROAD_VOLUME_AND_PREVIEW_LODS_QA.json':'a7ca81fb0b1c79f04ebf031d2f9e59e6d9f2152ac4c1ffac052b850aabb742c3',
 'R173_SOURCE_GEOMETRY_QA.json':'06759dc16a2ae7a55012b9ce04f9d8a1deef8d441dd9a27a0349adda423339ab',
}

class Blocked(ValueError): pass
def need(value, reason):
    if not value: raise Blocked(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def unique(pairs):
        d={}
        for key,value in pairs:
            need(key not in d,'R173_DUPLICATE_JSON_KEY')
            d[key]=value
        return d
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(Blocked('R173_NONFINITE_JSON')))

def validate(raw, *, expected_packet_sha=PACKET_SHA, report_sha=REPORT_SHA):
    need(isinstance(raw,bytes) and len(raw)<100_000,'R173_PACKET_SIZE')
    need(sha(raw)==expected_packet_sha,'R173_PACKET_DIGEST')
    p=strict(raw)
    need(isinstance(p,dict) and set(p)=={
      'schema','canonical_master_sha256','source_archive_sha256',
      'source_archive_glb_member_count','source_archive_bytes_transported',
      'source_archive_library_file_id','reports','glb_source_readback_observations',
      'scope','advancement_authorized'},'R173_PACKET_SCHEMA')
    need(p['schema']=='gg-r173-qa-transport-v1' and p['canonical_master_sha256']==MASTER_SHA
         and p['source_archive_sha256']==ARCHIVE_SHA and
         p['source_archive_library_file_id']==LIBRARY_ID,'R173_SOURCE_BINDING')
    need(p['source_archive_bytes_transported'] is False and p['advancement_authorized'] is False
         and p['scope']=='R173_REVIEW_QA_METADATA_ONLY_NOT_ASSET_CERTIFICATION',
         'R173_NO_ASSET_OR_PASS_SCOPE')
    reports=p['reports']
    need(isinstance(reports,dict) and set(reports)==set(report_sha),'R173_REPORT_COVERAGE')
    values={}
    for name,digest in report_sha.items():
        item=reports[name]
        need(isinstance(item,dict) and set(item)=={'sha256','raw_text'} and
             isinstance(item['raw_text'],str),'R173_REPORT_FORMAT:'+name)
        need(item['sha256']==digest and sha(item['raw_text'].encode('utf-8'))==digest,
             'R173_REPORT_CONTENT_CHANGED:'+name)
        values[name]=strict(item['raw_text'].encode('utf8'))
    bank=values['R173_BANK_DESIGN_AND_INTEGRATION_QA.json']
    road=values['R173_ROAD_VOLUME_AND_PREVIEW_LODS_QA.json']
    source=values['R173_SOURCE_GEOMETRY_QA.json']
    schematic=values['R173_R98_SCHEMATIC_CONTEXT_QA.json']
    need(bank.get('stage')=='DESIGN_REVIEW_NOT_PRODUCTION' and
         bank.get('AAA200')=='R172_BLOCKED_NOT_PROMOTED' and
         bank.get('artist_approval')=='PENDING' and
         bank.get('bridge_deck_walkability')=='UNKNOWN' and
         bank.get('water_final_level_gta_z')=='UNKNOWN_NO_PLANE_EXPORTED' and
         bank.get('R98_source_changed') is False, 'R173_BANK_UNSUPPORTED_PROMOTION')
    need(source.get('status')=='ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM' and
         source.get('collision_walkability')=='UNKNOWN' and
         source.get('water_final_Z')=='UNKNOWN' and
         source.get('AAA200_P0_P8')=='BLOCKED_IN_R172_REGISTER_NOT_PROMOTED' and
         source.get('source_master')=='R169-S1; WORK_STATE v241 after R172 blocked',
         'R173_SOURCE_HISTORICAL_LINEAGE_OR_STATUS')
    need(type(source.get('bridge_landings_pending')) is list and
         len(source['bridge_landings_pending'])==8 and
         len({x['name'] for x in source['bridge_landings_pending']})==8 and
         all(x.get('reason') for x in source['bridge_landings_pending']),
         'R173_PENDING_LANDINGS_NOT_PRESERVED')
    need(0.13 < source.get('max_centerline_designed_grade',0) < 0.14 and
         source.get('slope_over_5percent_total_m',0)>100,
         'R173_GRADE_RISK_SUPPRESSED')
    need(road.get('status')=='GEOMETRY_PREVIEW_COLLISION_VOLUMES_NOT_FIVEM_CONVERTED'
         and road.get('slope_collision_artistic')=='NOT_ACCEPTED'
         and schematic.get('acceptance')=='NONE'
         and schematic.get('water')=='XY BORDER ONLY -- ABSOLUTE WATER Z UNKNOWN',
         'R173_ROAD_OR_CONTEXT_PROMOTED')
    meshes=road.get('meshes')
    need(isinstance(meshes,dict) and set(meshes)=={'DETAILED','LOD1','LOD2'},
         'R173_LOD_SET')
    need(all(type(meshes[k].get('closed_mesh_edge_topology')) is bool and
                 meshes[k]['closed_mesh_edge_topology'] and
                 meshes[k].get('winding_consistent') is True for k in meshes),
         'R173_REPORTED_TOPOLOGY_FAILURE')
    need(meshes['DETAILED']['faces']>meshes['LOD1']['faces']>meshes['LOD2']['faces']>0,
         'R173_REPORTED_LOD_ORDER')
    glbs=p['glb_source_readback_observations']
    need(isinstance(glbs,list) and len(glbs)==p['source_archive_glb_member_count']==8,
         'R173_BINARY_MEMBER_COUNT')
    paths=[]
    for g in glbs:
        need(isinstance(g,dict) and set(g)=={
             'archive_member_path','sha256','member_bytes','glb_header_magic',
             'glb_header_version','glb_header_declared_bytes'},'R173_BINARY_METADATA_SCHEMA')
        path=g['archive_member_path'];paths.append(path)
        need(re.fullmatch(r'MODELS/GG_R173_[A-Z0-9_]+\.glb',path) and
             re.fullmatch(r'[0-9a-f]{64}',g['sha256']) and
             g['glb_header_magic']=='glTF' and g['glb_header_version']==2 and
             type(g['member_bytes']) is int and g['member_bytes']>12 and
             g['glb_header_declared_bytes']==g['member_bytes'],'R173_BINARY_LOCAL_READBACK_CLAIM')
    need(len(set(paths))==8,'R173_DUPLICATE_BINARY_MEMBER')
    return {
      'schema':'gg-r173-native-qa-metadata-verdict-v1',
      'source_archive_sha256':ARCHIVE_SHA,'packet_sha256':sha(raw),
      'qa_text_reports_verified':4,'binary_header_observations_reported':8,
      'binary_asset_contents_read_by_git':False,
      'qa_metadata_contents_and_consistency':'PASS',
      'scene_runtime_verified':False,'walkability_verified':False,
      'asset_specific_mg0':'UNKNOWN','artistic_approval_verified':False,
      'individual_rule_passes':0,'advancement_authorized':False,
      'unresolved':['R172_P0_BLOCKED','BRIDGE_LANDINGS_8_PENDING',
                     'WALKABILITY_UNKNOWN','WORLD_WATER_Z_UNKNOWN',
                     'GRADE_REVIEW_REQUIRED','ARTISTIC_ACCEPTANCE_PENDING']}

def main(argv=None):
    from broker_live_review import decode_file
    from git_judgment_origin import OriginAPI, PRIVATE_REPO_SHA
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref',required=True)
    args=p.parse_args(argv)
    try:
        need(re.fullmatch(r'[0-9a-f]{40}',args.ref),'R173_IMMUTABLE_REF')
        api=OriginAPI(os.environ['GH_REVIEW_TOKEN'],os.environ['GITHUB_REPOSITORY'])
        need(sha(api.repository.encode())==PRIVATE_REPO_SHA,'R173_REPOSITORY_ORIGIN')
        path='governance/supervisor/evidence/r173/GG_R173_QA_METADATA_ONLY_PROOF.json'
        packet=decode_file(api.call('GET','/contents/'+path+'?ref='+args.ref),path)
        print('R173_QA_NATIVE_METADATA_VERIFIED:'+json.dumps(validate(packet),sort_keys=True))
        return 0
    except (ValueError,TypeError,KeyError,OSError) as e:
        print('R173_QA_NATIVE_BLOCKED:'+str(e))
        return 1

if __name__=='__main__':raise SystemExit(main())
