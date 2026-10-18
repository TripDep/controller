"""C07 R145 independent synthetic 50-P2-rules source and asset-type tests."""
import copy
import json
import struct
import unittest
import zlib
from pathlib import Path
from c07_p2_fifty_asset_type_domain import inspect, TEXT, IDS, SourceBlocked
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_positive_native_process import Tests as Fixture,sha
from test_c07_native_output_oracle import two_triangles
from test_c07_a10_c10_original_evidence import png

def serialized(obj):return json.dumps(obj,sort_keys=True).encode()
def rgba_png():
    w=h=2
    pixels=b''.join(b'\0'+bytes((25,50,100,0))*w for _ in range(h))
    def c(k,p):return struct.pack('>I',len(p))+k+p+struct.pack('>I',zlib.crc32(k+p)&0xffffffff)
    return bytes((137,80,78,71,13,10,26,10))+c(b'IHDR',struct.pack('>IIBBBBB',w,h,8,6,0,0,0))+c(b'IDAT',zlib.compress(pixels))+c(b'IEND',b'')
class FiftyP2(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f=self.fx
        self.f.plan['phase']='P2'
        self.f.work['phase']='P2'
        self.f.plan['asset_type']='architecture'
        self.f.work['asset_type']='architecture'
        for n in range(61,111):
            sec=chr(ord('G')+(n-61)//10)
            rid='AAA-200-'+sec+'-'+str(n).zfill(3)
            clause,kind=TEXT[str(n)]
            self.f.inv['rules'][rid]={
              'family':'AAA-200','catalog_number':n,'catalog_section':sec,
              'catalog_phase':'P2','asset_type':kind,
              'source_sha256':'c'*64,'requirement':clause,
              'requirement_sha256':sha(clause.encode())}
        self.data={}
        self.add('NATIVE_EXPORT','scene.glb',two_triangles())
        self.add('BASELINE_SNAPSHOT','before.glb',two_triangles())
        for i,role in enumerate(('REFERENCE_IMAGE','VISUAL_VIEW_FRONT',
                  'VISUAL_VIEW_SIDE','VISUAL_VIEW_TOP','VISUAL_VIEW_UNDERSIDE',
                  'EROSION_REFERENCE','AREA_CONTEXT_IMAGE',
                  'WATER_EDGE_REFERENCE','WATER_RENDER_VIEW',
                  'FIVEM_RUNTIME_IMAGE'),1):
            self.add(role,role.lower()+'.png',png(13*i))
        self.add('P2_LEAF_CARD_PNG','leaves.png',rgba_png())
        self.add('P2_ARCH_CONTRACT','architecture.json',serialized({
             'triangle_budget':3000,'bevel_radius_mm':5,
             'edge_preservation_rules':['keep eaves'],
             'construction_policy':'ARCHITECTURE_1TO1',
             'structural_members':['column','beam'],
             'beam_ids':['B1'],'column_ids':['C1'],
             'connections':['C1-B1'],'symmetry_axis':'x',
             'intentional_asymmetry':['one gate'],
             'roof_slope_deg':35,'roof_support_connections':['B1-R1'],
             'door_height_m':2.1}))
        self.add('P2_ORGANIC_CONTRACT','rock.json',serialized({
             'natural_material':'granite','max_height_m':12,
             'modelling_method':'sculpt','seed':4,
             'erosion_material':'rock','triangle_budget':2000,
             'group_count':6}))
        self.add('P2_BOTANICAL_CONTRACT','flora.json',serialized({
            'species':'Prunus serrulata','climate_region':'temperate',
            'height_m':4,'branch_levels':['root','branch'],
            'branch_growth_rules':['upwards'],'leaf_representation':'ALPHA_CARDS',
            'alpha_pipeline':'alpha blend',
            'variation_asset_ids':['tree_a','tree_b'],
            'lod_distances_m':[10,30,90],'triangle_budget':3000}))
        self.add('P2_TERRAIN_CONTRACT','terrain.json',serialized({
            'water_level_z':5,'land_classes':['natural','rock'],
            'landing_ids':['landing_N','landing_S'],
            'contact_anchor_ids':['rock_to_water'],
            'bridge_anchor_ids':['bridge_N','bridge_S'],
            'triangle_budget':3000}))
        self.add('P2_SURVEY','survey.json',serialized({
           'samples':[{'x':i,'y':i,'z':i/2} for i in range(4)]}))
        self.add('P2_QA_REPORT','qa.json',serialized({'open_issues':['A01']}))
        self.add('P2_CONSTRUCTION_DRAWING','structure.pdf',b'%PDF-1.4\nsample drawing\n%%EOF')
        self.rebuild()
    def add(self,role,name,b):
        self.data[role]=(name,b)
        self.f.add_item(role,name,b)
    def rebuild(self):
        self.f.plan['p2_evidence_contract']={
          'original_artifact_sha256':{
              role:sha(b) for role,(_,b) in self.data.items()}}
        self.f.rebuild()
    def run_check(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                      source_loader=lambda p:Path(p).read_bytes())
    def test_50_literal_P2_rule_ids_and_100_named_individual_checks(self):
        r=self.run_check()
        self.assertEqual(r['canonical_source_rule_count'],50)
        self.assertEqual(r['named_domain_probes'],100)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertEqual(r['actual_due_rules'],20)
        self.assertEqual(r['other_asset_type_rules'],30)
        self.assertEqual(r['full_semantic_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        names=[]
        for rid,row in r['rules'].items():
            if row['applicability']=='DUE':
                names+=list(row['original_native_domain_predicates'])
                self.assertEqual(len(row['original_native_domain_predicates']),2)
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
            else:
                self.assertEqual(row['machine_scope'],'N_A_ASSET_TYPE')
                self.assertEqual(row['individual_mg0'],'NOT_DUE')
                self.assertFalse(row['original_native_domain_predicates'])
        self.assertEqual(len(names),40)
    def test_each_of_50_literal_original_clauses_tampering_blocks(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='fake compliance'
            with self.subTest(id=rid):
                with self.assertRaisesRegex(SourceBlocked,'R145_CANONICAL_EXACT_P2_RULE_CHANGED'):
                    self.run_check()
            self.f.inv['rules'][rid]['requirement']=old
    def test_each_of_50_original_requirement_source_sha_tampering_blocks(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='f'*64
            with self.subTest(id=rid):
                with self.assertRaisesRegex(SourceBlocked,'R145_CANONICAL_EXACT_P2_RULE_CHANGED'):
                    self.run_check()
            self.f.inv['rules'][rid]['source_sha256']=old
    def test_asset_type_applicability_organic_exact_10(self):
        self.f.work['asset_type']='organic'
        self.f.plan['asset_type']='organic'
        self.rebuild()
        x=self.run_check()
        self.assertEqual(x['actual_due_rules'],10)
        self.assertEqual(x['other_asset_type_rules'],40)
        self.assertEqual(x['rules']['AAA-200-G-061']['applicability'],'N_A_ASSET_TYPE')
        self.assertEqual(x['rules']['AAA-200-I-081']['applicability'],'DUE')
    def test_asset_type_applicability_vegetation_exact_10(self):
        self.f.work['asset_type']='vegetation'
        self.f.plan['asset_type']='vegetation'
        self.rebuild()
        x=self.run_check()
        self.assertEqual(x['actual_due_rules'],10)
        self.assertEqual(x['rules']['AAA-200-J-095']['applicability'],'DUE')
        self.assertEqual(x['rules']['AAA-200-J-095']['full_rule_semantics'],'UNKNOWN')
    def test_asset_type_applicability_terrain_exact_10(self):
        self.f.work['asset_type']='terrain'
        self.f.plan['asset_type']='terrain'
        self.rebuild()
        x=self.run_check()
        self.assertEqual(x['actual_due_rules'],10)
        self.assertEqual(x['rules']['AAA-200-K-101']['applicability'],'DUE')
        self.assertEqual(x['rules']['AAA-200-I-081']['applicability'],'N_A_ASSET_TYPE')
    def test_P1_cannot_run_P2_evidence(self):
        self.f.plan['phase']='P1';self.f.work['phase']='P1'
        self.rebuild()
        with self.assertRaisesRegex(SourceBlocked,'R145_CANONICAL_P2_OR_TYPE'):
            self.run_check()
    def test_original_native_binary_tamper_blocks(self):
        (self.f.root/'scene.glb').write_bytes(b'not the original GLB')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.run_check()
    def test_original_survey_numeric_source_vs_forged_artifact(self):
        self.f.work['asset_type']='terrain'
        self.f.plan['asset_type']='terrain'
        self.rebuild()
        x=self.run_check()
        self.assertTrue(x['rules']['AAA-200-K-101']['original_native_domain_predicates'][
             'original_four_numeric_world_points_checked'])
        self.assertEqual(x['rules']['AAA-200-K-101']['individual_mg0'],'UNKNOWN')
    def test_glb_raster_no_false_botanical_or_fivem_pass(self):
        self.f.work['asset_type']='vegetation'
        self.f.plan['asset_type']='vegetation'
        self.rebuild()
        d=self.run_check()
        self.assertEqual(d['rules']['AAA-200-J-100']['full_rule_semantics'],'UNKNOWN')
        self.assertEqual(d['rules']['AAA-200-J-095']['individual_mg0'],'UNKNOWN')
    def test_cross_attempt_replay_rejected(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='f'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.run_check()
if __name__=='__main__':unittest.main()
