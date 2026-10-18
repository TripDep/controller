"""C07 R147 forty source-bound P6/P7/P8 original and adversarial tests."""
import copy
import json
import unittest
from pathlib import Path
from c07_p678_forty_native_domain import inspect, TEXT, IDS, Blocked
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_positive_native_process import Tests as Fixture,sha
from test_c07_native_output_oracle import two_triangles
from test_c07_r124_positive_process import test_glb
from test_c07_a10_c10_original_evidence import png

def encode(x):return json.dumps(x,sort_keys=True).encode()
class P678Forty(unittest.TestCase):
    def setUp(self):
        self.fixture=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture
        self.f.plan['phase']='P6'
        self.f.work['phase']='P6'
        for n in list(range(151,171))+list(range(181,201)):
            sec='P' if n<=160 else 'Q' if n<=170 else 'S' if n<=190 else 'T'
            rid='AAA-200-'+sec+'-'+str(n).zfill(3)
            text,phase=TEXT[str(n)]
            self.f.inv['rules'][rid]={
              'family':'AAA-200','catalog_number':n,
              'catalog_section':sec,'catalog_phase':phase,'asset_type':'all',
              'source_sha256':'c'*64,'requirement':text,
              'requirement_sha256':sha(text.encode())}
        self.art={}
        self.add('NATIVE_EXPORT','scene.glb',two_triangles())
        self.add('COLLISION_PROXY','collision.glb',test_glb())
        self.add('BASELINE_SNAPSHOT','prior.glb',test_glb())
        self.add('NATIVE_REIMPORT','reimport.glb',two_triangles())
        self.add('P6_COLLISION_PLAN','collision.json',encode({
          'solid_surface_ids':['bridge','gate'],
          'passage_collision_ids':['north gate','south gate'],
          'walkable_zone_ids':['main path'],
          'vehicle_clearance_m':3}))
        self.add('P7_FIVEM_PLAN','fivem.json',encode({
          'resource_files':['fxmanifest.lua','scene.ydr'],
          'drawable_role':'DRAWABLE',
          'texture_role':'TEXTURE_DICTIONARY',
          'archetypes':['gate'], 'map_placements':[{'name':'gate'}],
          'collision_names':['gate_coll'],
          'shader_names':['normal_spec']}))
        self.add('P8_DELIVERY_QA','delivery_qa.json',encode({
          'status':'PENDING','owner_approved':False,
          'issue_ids':['broken wall'],'root_cause_ids':['z-axis mismatch']}))
        self.add('P8_REQUIRED_FILES','required.json',encode({
          'files':['SOURCE_EDITABLE','NATIVE_EXPORT','DELIVERY_PACKAGE']}))
        for i,role in enumerate(('VISUAL_VIEW_FRONT','VISUAL_VIEW_REAR','VISUAL_VIEW_LEFT',
              'VISUAL_VIEW_RIGHT','VISUAL_VIEW_TOP','VISUAL_VIEW_UNDERSIDE',
              'P8_MATERIAL_RENDER','P8_AREA_CONTEXT'),1):
            self.add(role,role.lower()+'.png',png(9*i))
        for role,suffix in (('YDR_DRAWABLE','ydr'),('YTD_TEXTURE','ytd'),
              ('YTYP_ARCHETYPES','ytyp'),('YMAP_PLACEMENT','ymap'),
              ('YBN_COLLISION','ybn')):
            self.add(role,role.lower()+'.'+suffix,b'original-native-fixture')
        self.add('DELIVERY_PACKAGE','scene.zip',self.f.make_zip())
        self.sync()
    def add(self,role,path,raw):
        self.art[role]=raw
        self.f.add_item(role,path,raw)
    def sync(self):
        self.f.plan['p678_evidence_contract']={
            'original_artifact_sha256':{
               role:sha(b) for role,b in self.art.items()} |
                {'SOURCE_EDITABLE':self.f.items['SOURCE_EDITABLE']['sha256']}}
        self.f.rebuild()
    def review(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
            source_loader=lambda p:Path(p).read_bytes())
    def test_phase_P6_10_rules_due_P7_20_P8_40(self):
        x=self.review()
        self.assertEqual(x['source_rule_count'],40)
        self.assertEqual(x['due_rule_count'],10)
        self.assertEqual(x['future_rule_count'],30)
        self.assertEqual(x['named_machine_criteria'],80)
        self.assertEqual(set(x['rules']),set(IDS))
        self.assertEqual(x['full_semantic_passes'],0)
        self.assertEqual(x['individual_mg0_passes'],0)
        self.assertFalse(x['advancement_authorized'])
        self.f.plan['phase']='P7';self.f.work['phase']='P7';self.sync()
        self.assertEqual(self.review()['due_rule_count'],20)
        self.f.plan['phase']='P8';self.f.work['phase']='P8';self.sync()
        x=self.review()
        self.assertEqual(x['due_rule_count'],40)
        self.assertEqual(x['future_rule_count'],0)
        names=[]
        for row in x['rules'].values():
            self.assertEqual(len(row['native_original_machine_evidence']),2)
            self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
            self.assertEqual(row['individual_mg0'],'UNKNOWN')
            names+=list(row['native_original_machine_evidence'])
        self.assertEqual(len(set(names)),80)
    def test_all_40_source_literal_tamper_blocks(self):
        for rid in IDS:
            original=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='FAKE PASS'
            with self.subTest(rule=rid):
                with self.assertRaisesRegex(Blocked,'R147_CANONICAL_CLAUSE_DRIFT'):
                    self.review()
            self.f.inv['rules'][rid]['requirement']=original
    def test_all_40_source_sha_tamper_blocks(self):
        for rid in IDS:
            original=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='f'*64
            with self.subTest(rule=rid):
                with self.assertRaisesRegex(Blocked,'R147_CANONICAL_CLAUSE_DRIFT'):
                    self.review()
            self.f.inv['rules'][rid]['source_sha256']=original
    def test_P5_phase_not_yet_due_rejected(self):
        self.f.plan['phase']='P5';self.f.work['phase']='P5';self.sync()
        with self.assertRaisesRegex(Blocked,'R147_ORIGINAL_P678_SCOPE_REQUIRED'):
            self.review()
    def test_original_ZIP_from_original_bytes_matches_export_without_approval(self):
        self.f.plan['phase']='P8';self.f.work['phase']='P8'
        # Regenerate exact current work manifest to bind same attempt.
        self.add('DELIVERY_PACKAGE','scene.zip',self.f.make_zip())
        self.sync()
        x=self.review()['rules']['AAA-200-T-191']
        self.assertTrue(x['native_original_machine_evidence'][
            'delivery_original_zip_export_manifest_matches'])
        self.assertEqual(x['full_rule_semantics'],'UNKNOWN')
        self.assertEqual(x['individual_mg0'],'UNKNOWN')
    def test_wrong_attempt_ZIP_downgrades_without_false_delivery_PASS(self):
        self.f.plan['phase']='P8';self.f.work['phase']='P8'
        self.add('DELIVERY_PACKAGE','scene.zip',self.f.make_zip(wrong_attempt=True))
        self.sync()
        row=self.review()['rules']['AAA-200-T-191']
        self.assertFalse(row['native_original_machine_evidence'][
           'delivery_original_zip_export_manifest_matches'])
    def test_original_binary_file_modified_after_audit_blocks(self):
        (self.f.root/'scene.glb').write_bytes(b'changed non-original content')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.review()
    def test_original_C07_audit_cross_attempt_replay_blocks(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='e'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.review()
    def test_original_P8_reports_never_certify_owner(self):
        self.f.plan['phase']='P8';self.f.work['phase']='P8';self.sync()
        x=self.review()
        self.assertEqual(x['rules']['AAA-200-T-200']['individual_mg0'],'UNKNOWN')
        self.assertEqual(x['rules']['AAA-200-S-190']['owner_acceptance'],'UNKNOWN')
if __name__=='__main__':unittest.main()
