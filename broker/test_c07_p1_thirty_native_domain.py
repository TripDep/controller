"""R144 adversarial canonical original P1 source tests. All assets synthetic only."""
import copy
import json
import unittest
from pathlib import Path
from c07_p1_thirty_native_domain import inspect, IDS, TEXT, P1EvidenceBlocked
from c07_positive_native_process import NativeEvidenceBlocked
from c07_a10_c10_original_evidence import NOTE_SCHEMA
from test_c07_positive_native_process import Tests as Fixture, sha
from test_c07_native_output_oracle import two_triangles
from test_c07_a10_c10_original_evidence import png
from c07_positive200_evidence import R122_FROZEN_IDS

def encode(doc):return json.dumps(doc,sort_keys=True,ensure_ascii=False).encode()

class P1Thirty(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f=self.fx
        self.f.plan['phase']='P1'
        self.f.work['phase']='P1'
        for n in range(31,61):
            section='D' if n<=40 else 'E' if n<=50 else 'F'
            rid='AAA-200-'+section+'-'+str(n).zfill(3)
            text=TEXT[str(n)]
            self.f.inv['rules'][rid]={
                'family':'AAA-200','catalog_number':n,
                'catalog_section':section,'catalog_phase':'P1',
                'requirement':text,'source_sha256':'c'*64,
                'requirement_sha256':sha(text.encode())}
        self.contents={}
        self.put('NATIVE_EXPORT','scene.glb',two_triangles())
        self.put('SECONDARY_EXPORT','other.glb',two_triangles())
        self.put('BASELINE_SNAPSHOT','before.glb',two_triangles())
        for num,role in enumerate(('VISUAL_VIEW_FRONT','VISUAL_VIEW_LEFT',
                         'VISUAL_VIEW_RIGHT','VISUAL_VIEW_TOP',
                         'REFERENCE_IMAGE','IMAGE_MATERIAL',
                         'SCENE_PEER_REFERENCE'),1):
            self.put(role,role.lower()+'.png',png(num*19))
        self.put('P1_SCENE_CONTRACT','p1_scene.json',encode({
           'style_language':'Classical Chinese garden','area_id':'South',
           'void_zones':['central pond'],'footprint_m':[1,1],
           'expected_bbox_local':{'min':[0,0,0],'max':[1,1,1]},
           'origin_xyz':[0,0,0],'coordinate_basis':'Z_UP',
           'named_anchors':{'bridge':[0,0,0],'gate':[1,1,1]},
           'locked_original_sha256':self.f.items['SOURCE_EDITABLE']['sha256'],
           'player_height_m':1.75,'player_camera':{'eye':'front'},
           'component_roles':['bridge connection','gate frame'],
           'variation_rules':['no cloned flowers'],
           'repeat_patterns':['alternating columns'],
           'entrances':['north'],'exits':['south'],
           'allowed_zone_classes':['pedestrian'],
           'player_width_m':0.55,'cameras':{'front':1,'left':2,'right':3,'top':4},
           'blockout_triangle_budget':1000,
           'blockout_acceptance_criteria':['valid path clearances'],
           'orientation_xyz_deg':[0,0,0], 'building_clearance_m':3
        }))
        self.put('P1_PALETTE','palette.json',encode({'colors':['dark wood','stone']}))
        self.put('P1_QA_REPORT','qa.json',encode({'open_findings':['BAD_ALIGNMENT']}))
        self.put('P1_PATHS_GEOJSON','paths.json',encode({
           'features':[{'geometry':{'type':'LineString','coordinates':[[0,0],[1,1]]}}],
           'path_classes':['main','secondary'],
           'zones':[{'polygon':[[0,0],[1,0],[1,1],[0,0]],
                     'allowed_actors':['pedestrian']}]}))
        self.put('P1_TERRAIN_SAMPLES','terrain.json',
            encode({'samples_z':[0,1,2]}))
        self.rebuild()
    def put(self,role,name,data):
        self.contents[role]=(name,data)
        self.f.add_item(role,name,data)
    def rebuild(self):
        self.f.plan['p1_evidence_contract']={
            'original_artifact_sha256':{
                role:sha(data) for role,(_name,data) in self.contents.items()
            }|{'SOURCE_EDITABLE':self.f.items['SOURCE_EDITABLE']['sha256']}
        }
        self.f.rebuild()
    def review(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
            source_loader=lambda p:Path(p).read_bytes())
    def test_exact_30_individual_P1_and_90_unique_predicates(self):
        r=self.review()
        self.assertEqual(r['source_rules_examined'],30)
        self.assertEqual(r['native_domain_criteria'],90)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertTrue(set(IDS).isdisjoint(R122_FROZEN_IDS))
        self.assertEqual(r['full_semantic_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        names=[]
        for rid,item in r['rules'].items():
            with self.subTest(rule=rid):
                self.assertEqual(item['individual_mg0'],'UNKNOWN')
                self.assertEqual(item['full_rule_semantics'],'UNKNOWN')
                self.assertFalse(item['advancement_authorized'])
                self.assertEqual(len(item['original_native_measured_criteria']),3)
                names+=list(item['original_native_measured_criteria'])
        self.assertEqual(len(set(names)),90)
    def test_verified_geometry_contract_really_observed_not_mg0(self):
        r=self.review()
        n=r['rules']['AAA-200-E-047']
        self.assertTrue(all(n['original_native_measured_criteria'].values()))
        self.assertEqual(n['native_scope'],'SOURCE_SCOPE_OBSERVED')
        self.assertEqual(n['individual_mg0'],'UNKNOWN')
        self.assertEqual(n['full_rule_semantics'],'UNKNOWN')
    def test_each_literal_rule_change_fails_closed(self):
        for rid in IDS:
            prior=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='fake source PASS'
            with self.subTest(rule=rid):
                with self.assertRaisesRegex(P1EvidenceBlocked,'R144_CANONICAL_P1_RULE_CHANGED'):
                    self.review()
            self.f.inv['rules'][rid]['requirement']=prior
    def test_each_rule_source_sha_change_fails_closed(self):
        for rid in IDS:
            prior=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='e'*64
            with self.subTest(rule=rid):
                with self.assertRaisesRegex(P1EvidenceBlocked,'R144_CANONICAL_P1_RULE_CHANGED'):
                    self.review()
            self.f.inv['rules'][rid]['source_sha256']=prior
    def test_phase_P0_must_not_run_P1_rules(self):
        self.f.plan['phase']='P0';self.f.work['phase']='P0';self.f.rebuild()
        with self.assertRaisesRegex(P1EvidenceBlocked,'R144_P1_ORIGINAL_PHASE'):
            self.review()
    def test_corrupted_original_image_not_interpreted_as_valid(self):
        from c07_a10_c10_original_evidence import original_image
        p=self.f.root/'visual_view_front.png'
        raw=bytearray(p.read_bytes());raw[29]^=255
        self.assertIsNone(original_image(bytes(raw)))
    def test_original_file_binary_modified_is_failure(self):
        (self.f.root/'scene.glb').write_bytes(b'changed fake native GLB')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.review()
    def test_declared_expected_bbox_wrong_does_not_grant_positive(self):
        scene=json.loads(self.contents['P1_SCENE_CONTRACT'][1])
        scene['expected_bbox_local']['max']=[3,3,3]
        self.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        self.rebuild()
        x=self.review()['rules']['AAA-200-F-052']
        self.assertFalse(x['original_native_measured_criteria'][
            'original_local_bounds_match_pre_D_expected_extent'])
        self.assertEqual(x['full_rule_semantics'],'UNKNOWN')
    def test_unpinned_reference_not_accepted(self):
        self.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop('REFERENCE_IMAGE')
        self.f.rebuild()
        x=self.review()['rules']['AAA-200-D-031']
        self.assertFalse(x['original_native_measured_criteria'][
            'original_style_reference_image_decoded'])
    def test_cross_attempt_replay_rejected(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='d'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.review()
    def test_no_release_approval_from_source_only(self):
        doc=self.review()
        self.assertEqual(doc['full_semantic_passes'],0)
        self.assertEqual(doc['individual_mg0_passes'],0)
        self.assertTrue(all(x['artistic_approval']=='UNKNOWN'
                 for x in doc['rules'].values()))
if __name__=='__main__':unittest.main()
