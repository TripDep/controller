"""Transport regression tests use synthetic metadata only, never production assets."""
import copy
import json
import unittest

from qa_transport_r173 import validate,sha,Blocked,MASTER_SHA,ARCHIVE_SHA,LIBRARY_ID

def pack():
    bank={'stage':'DESIGN_REVIEW_NOT_PRODUCTION','AAA200':'R172_BLOCKED_NOT_PROMOTED',
          'artist_approval':'PENDING','bridge_deck_walkability':'UNKNOWN',
          'water_final_level_gta_z':'UNKNOWN_NO_PLANE_EXPORTED','R98_source_changed':False}
    source={'status':'ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM',
            'collision_walkability':'UNKNOWN','water_final_Z':'UNKNOWN',
            'AAA200_P0_P8':'BLOCKED_IN_R172_REGISTER_NOT_PROMOTED',
            'source_master':'R169-S1; WORK_STATE v241 after R172 blocked',
            'bridge_landings_pending':[{'name':str(i),'reason':'Still pending'} for i in range(8)],
            'max_centerline_designed_grade':0.13793829339808691,
            'slope_over_5percent_total_m':136.24}
    road={'status':'GEOMETRY_PREVIEW_COLLISION_VOLUMES_NOT_FIVEM_CONVERTED',
          'slope_collision_artistic':'NOT_ACCEPTED',
          'meshes':{k:{'faces':f,'closed_mesh_edge_topology':True,'winding_consistent':True}
                    for k,f in [('DETAILED',8840),('LOD1',1140),('LOD2',720)]}}
    schematic={'acceptance':'NONE','water':'XY BORDER ONLY -- ABSOLUTE WATER Z UNKNOWN'}
    items={
      'R173_BANK_DESIGN_AND_INTEGRATION_QA.json':bank,
      'R173_SOURCE_GEOMETRY_QA.json':source,
      'R173_ROAD_VOLUME_AND_PREVIEW_LODS_QA.json':road,
      'R173_R98_SCHEMATIC_CONTEXT_QA.json':schematic}
    report={}
    for k,v in items.items():
        raw=json.dumps(v,sort_keys=True)
        report[k]={'sha256':sha(raw.encode()),'raw_text':raw}
    glb=[{'archive_member_path':'MODELS/GG_R173_MODEL_'+str(i)+'.glb',
          'sha256':'a'*64,'member_bytes':100+i,
          'glb_header_magic':'glTF','glb_header_version':2,
          'glb_header_declared_bytes':100+i} for i in range(8)]
    return {'schema':'gg-r173-qa-transport-v1',
      'canonical_master_sha256':MASTER_SHA,
      'source_archive_sha256':ARCHIVE_SHA,
      'source_archive_glb_member_count':8,
      'source_archive_bytes_transported':False,
      'source_archive_library_file_id':LIBRARY_ID,
      'reports':report,'glb_source_readback_observations':glb,
      'scope':'R173_REVIEW_QA_METADATA_ONLY_NOT_ASSET_CERTIFICATION',
      'advancement_authorized':False}
def serialize(v):return (json.dumps(v,sort_keys=True)+'\n').encode()
def assess(v):
    raw=serialize(v)
    return validate(raw,expected_packet_sha=sha(raw),
      report_sha={k:vv['sha256'] for k,vv in v['reports'].items()})

class Tests(unittest.TestCase):
    def test_admissible_qa_text_is_not_asset_certification(self):
        r=assess(pack())
        self.assertEqual(r['qa_metadata_contents_and_consistency'],'PASS')
        self.assertEqual(r['individual_rule_passes'],0)
        self.assertEqual(r['asset_specific_mg0'],'UNKNOWN')
        self.assertFalse(r['advancement_authorized'])
        self.assertFalse(r['binary_asset_contents_read_by_git'])
    def test_fake_work_pass_rejected(self):
        v=pack();v['advancement_authorized']=True
        with self.assertRaisesRegex(Blocked,'R173_NO_ASSET_OR_PASS_SCOPE'):assess(v)
    def test_absent_qa_report_rejected(self):
        v=pack();v['reports'].pop('R173_SOURCE_GEOMETRY_QA.json')
        with self.assertRaisesRegex(Blocked,'R173_REPORT_COVERAGE'):assess(v)
    def test_report_content_tamper_rejected(self):
        v=pack();v['reports']['R173_BANK_DESIGN_AND_INTEGRATION_QA.json']['raw_text']+='x'
        with self.assertRaisesRegex(Blocked,'R173_REPORT_CONTENT_CHANGED'):assess(v)
    def test_suppressed_pending_landings_rejected(self):
        v=pack();k='R173_SOURCE_GEOMETRY_QA.json';v['reports'][k]['raw_text']=json.dumps({
             **json.loads(v['reports'][k]['raw_text']),'bridge_landings_pending':[]})
        v['reports'][k]['sha256']=sha(v['reports'][k]['raw_text'].encode())
        with self.assertRaisesRegex(Blocked,'R173_PENDING_LANDINGS_NOT_PRESERVED'):assess(v)
    def test_invalid_glb_header_claim_rejected(self):
        v=pack();v['glb_source_readback_observations'][0]['glb_header_version']=1
        with self.assertRaisesRegex(Blocked,'R173_BINARY_LOCAL_READBACK_CLAIM'):assess(v)
    def test_packet_digest_bound_before_semantics(self):
        raw=serialize(pack())
        with self.assertRaisesRegex(Blocked,'R173_PACKET_DIGEST'):
            validate(raw,expected_packet_sha='0'*64)

if __name__=='__main__':unittest.main()
