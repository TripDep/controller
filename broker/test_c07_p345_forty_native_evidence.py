"""C07 R146 original-source adversarial P3/P4/P5 domain proof tests."""
import copy
import json
import unittest
from pathlib import Path
from c07_p345_forty_native_evidence import inspect, TEXT, IDS, QAOriginalBlocked
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_positive_native_process import Tests as Fixture,sha
from test_c07_native_output_oracle import two_triangles
from test_c07_a10_c10_original_evidence import png

def encoded(obj):return json.dumps(obj,sort_keys=True).encode()
class P345Forty(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f=self.fx
        self.f.work['phase']='P3'
        self.f.plan['phase']='P3'
        for n in range(111,151):
            sec='L' if n<=120 else 'M' if n<=130 else 'N' if n<=140 else 'O'
            rid='AAA-200-'+sec+'-'+str(n).zfill(3)
            req,phase=TEXT[str(n)]
            self.f.inv['rules'][rid]={
                'family':'AAA-200','catalog_number':n,
                'catalog_section':sec,'catalog_phase':phase,'asset_type':'all',
                'source_sha256':'c'*64,'requirement':req,
                'requirement_sha256':sha(req.encode())}
        self.art={}
        self.add('NATIVE_EXPORT','scene.glb',two_triangles())
        self.add('LOD_EXPORT','far.glb',two_triangles())
        self.add('P3_UV_POLICY','uv.json',encoded({'texel_px_per_m':500,'atlas_max_pixels':2048}))
        self.add('P4_MATERIAL_PLAN','material.json',encoded({
            'physical_material_classes':['wood','stone','metal','glass','plaster'],
            'roughness_target':0.5,'surface_variations':['wood a','wood b'],
            'weathering_level':0.2,'fivem_shader_profile':'GTA Shader'}))
        self.add('P4_LIGHTING_QA','lighting.json',encoded({
            'neutral_lux':500,'modes':['neutral','cinematic'],
            'player_eye_height_m':1.7,'presentation_mode':'STUDIO_ONLY'}))
        self.add('P5_PERF_BUDGET','perf.json',encoded({
            'max_triangles':200,'material_count_budget':8,
            'shared_material_ids':['gold wood','black metal'],
            'max_texture_mb':100,'target_frame_ms':16.7}))
        self.add('P345_QA_REPORT','qa.json',encoded({'unresolved_findings':['lighting issue']}))
        for i,role in enumerate(('VISUAL_VIEW_FRONT','VISUAL_VIEW_REAR','VISUAL_VIEW_SIDE',
          'VISUAL_VIEW_TOP','VISUAL_VIEW_UNDERSIDE','LIGHT_NEUTRAL_VIEW',
          'LIGHT_CINEMATIC_VIEW','LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW',
          'MATERIAL_REFERENCE_IMAGE','TEXTURE_RASTER_IMAGE','UV_GRID_IMAGE',
          'EXPORT_REIMPORT_VIEW','WEATHERING_REFERENCE','REFLECTION_VIEW',
          'LOD_NEAR_VIEW','LOD_FAR_VIEW','VEGETATION_ALPHA_IMAGE'),1):
            self.add(role,role.lower()+'.png',png(i+20))
        self.sync()
    def add(self,role,path,raw):
        self.art[role]=raw
        self.f.add_item(role,path,raw)
    def sync(self):
        self.f.plan['p345_evidence_contract']={
            'original_artifact_sha256':{
                role:sha(raw) for role,raw in self.art.items()}|
                {'SOURCE_EDITABLE':self.f.items['SOURCE_EDITABLE']['sha256']}
        }
        self.f.rebuild()
    def report(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                       source_loader=lambda p:Path(p).read_bytes())
    def test_p3_exact10_due_and30_future_without_mg0(self):
        r=self.report()
        self.assertEqual(r['source_rule_count'],40)
        self.assertEqual(r['applicable_phase_rule_count'],10)
        self.assertEqual(r['future_phase_rule_count'],30)
        self.assertEqual(r['native_named_domain_checks'],80)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertEqual(r['full_rule_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        labels=[]
        for rule,item in r['rules'].items():
            if item['applicability']=='DUE':
                self.assertEqual(item['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(item['individual_mg0'],'UNKNOWN')
                self.assertEqual(len(item['machine_observations']),2)
                labels+=list(item['machine_observations'])
            else:
                self.assertEqual(item['full_rule_semantics'],'NOT_DUE')
                self.assertEqual(item['individual_mg0'],'NOT_DUE')
                self.assertFalse(item['machine_observations'])
        self.assertEqual(len(set(labels)),20)
    def test_p4_30_due_and_p5_40_due(self):
        self.f.work['phase']='P4';self.f.plan['phase']='P4';self.sync()
        r=self.report()
        self.assertEqual(r['applicable_phase_rule_count'],30)
        self.assertEqual(r['future_phase_rule_count'],10)
        self.f.work['phase']='P5';self.f.plan['phase']='P5';self.sync()
        r=self.report()
        self.assertEqual(r['applicable_phase_rule_count'],40)
        self.assertEqual(r['future_phase_rule_count'],0)
    def test_all_40_original_source_literal_tamper_blocks(self):
        for rule in IDS:
            original=self.f.inv['rules'][rule]['requirement']
            self.f.inv['rules'][rule]['requirement']='FAKE PASS'
            with self.subTest(rule=rule):
                with self.assertRaisesRegex(QAOriginalBlocked,'R146_CANONICAL_ORIGINAL_SOURCE_CHANGED'):
                    self.report()
            self.f.inv['rules'][rule]['requirement']=original
    def test_all_40_source_sha_tamper_blocks(self):
        for rule in IDS:
            original=self.f.inv['rules'][rule]['source_sha256']
            self.f.inv['rules'][rule]['source_sha256']='f'*64
            with self.subTest(rule=rule):
                with self.assertRaisesRegex(QAOriginalBlocked,'R146_CANONICAL_ORIGINAL_SOURCE_CHANGED'):
                    self.report()
            self.f.inv['rules'][rule]['source_sha256']=original
    def test_p2_phase_is_not_eligible(self):
        self.f.work['phase']='P2';self.f.plan['phase']='P2';self.sync()
        with self.assertRaisesRegex(QAOriginalBlocked,'R146_CANONICAL_PHASE'):
            self.report()
    def test_true_native_glb_geometry_with_budget_is_real_machine_measure(self):
        self.f.work['phase']='P5';self.f.plan['phase']='P5';self.sync()
        r=self.report()
        v=r['rules']['AAA-200-O-142']
        self.assertTrue(all(v['machine_observations'].values()))
        self.assertEqual(v['full_rule_semantics'],'UNKNOWN')
        self.assertEqual(v['individual_mg0'],'UNKNOWN')
    def test_reference_raster_original_source_modified_rejected(self):
        (self.f.root/'visual_view_front.png').write_bytes(b'wrong synthetic image')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.report()
    def test_glb_original_bytes_modified_rejected(self):
        (self.f.root/'scene.glb').write_bytes(b'not matching source')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.report()
    def test_cross_attempt_replay_rejected(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='e'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.report()
    def test_no_benchmark_pass_from_budget_document(self):
        self.f.work['phase']='P5';self.f.plan['phase']='P5';self.sync()
        r=self.report()['rules']['AAA-200-O-150']
        self.assertFalse(r['machine_observations']['original_native_runtime_benchmark_log_source_read'])
        self.assertEqual(r['full_rule_semantics'],'UNKNOWN')
if __name__=='__main__':unittest.main()
