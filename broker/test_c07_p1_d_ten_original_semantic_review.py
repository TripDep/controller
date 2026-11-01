"""Adversarial original-byte checks for the complete D031-D040 P1 family.

Fixtures exercise positive source binding and negative original-byte changes.
These are deliberately NOT tests of owner artistic acceptance or MG0.
"""
import copy
import json
import unittest
from pathlib import Path
from test_c07_p1_thirty_native_domain import P1Thirty, encode
from c07_p1_d_ten_original_semantic_review import evaluate, IDS, CRITERIA, ROLES
from c07_native_source_rule_replayers import FULL_LITERAL_REVIEWED

class P1DDesignOriginalTests(unittest.TestCase):
    def fixture(self):
        t=P1Thirty('test_exact_30_individual_P1_and_90_unique_predicates')
        t.setUp()
        self.addCleanup(t.doCleanups)
        # Genuine synthetic P1 void polygon (not a descriptive label) and
        # bounded repetition criterion: both must be measured from GLB bytes.
        scene=json.loads(t.contents['P1_SCENE_CONTRACT'][1])
        scene['void_zones']=[[[0.4,0.4],[0.6,0.4],
                              [0.6,0.6],[0.4,0.6]]]
        scene['min_void_fraction']=0.01
        scene['max_void_fraction']=0.1
        scene['max_repeated_signature_ratio']=1
        t.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        t.rebuild()
        return t
    def context(self,t):
        f=t.f
        return dict(inventory=f.inv,plan=f.plan,controller=f.controller,
                    asset=f.asset,step=f.step,work=f.work,
                    source_loader=lambda p:Path(p).read_bytes())
    def test_all_ten_original_sources_reopened_with_distinct_measures(self):
        t=self.fixture()
        r=evaluate(self.context(t))
        self.assertEqual(set(r['rows']),set(IDS))
        self.assertEqual(len({k for v in r['rows'].values()
                              for k in v['checks']}),30)
        self.assertEqual(r['full_semantic_passes'],0)
        self.assertEqual(r['mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        for rid,row in r['rows'].items():
            with self.subTest(rule=rid):
                self.assertEqual(len(row['checks']),3)
                self.assertTrue(all(type(v) is bool for v in row['checks'].values()))
                self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertTrue(row['checks'][CRITERIA[int(rid[-3:])][0]]
                                or row['checks'][CRITERIA[int(rid[-3:])][1]])
    def test_each_rule_fails_its_original_pin_if_removed(self):
        for n in range(31,41):
            with self.subTest(rule=n):
                t=self.fixture()
                original=evaluate(self.context(t))['rows'][IDS[n-31]]['checks']
                role=ROLES[n][0]
                t.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(role)
                t.f.rebuild()
                after=evaluate(self.context(t))['rows'][IDS[n-31]]['checks']
                self.assertNotEqual(original,after)
                self.assertFalse(after[CRITERIA[n][0]])
    def test_original_bytes_changed_without_new_audit_fail_closed(self):
        t=self.fixture()
        t.f.root.joinpath('scene.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):
            evaluate(self.context(t))
    def test_wrong_attempt_cannot_reuse_original_measurements(self):
        t=self.fixture()
        ctx=self.context(t)
        ctx['work']=copy.deepcopy(ctx['work'])
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            evaluate(ctx)
    def test_color_distance_uses_decoded_pixels_not_image_file_names(self):
        t=self.fixture()
        scene=json.loads(t.contents['P1_SCENE_CONTRACT'][1])
        scene['style_max_mean_rgb_delta']=0
        t.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        t.rebuild()
        checks=evaluate(self.context(t))['rows'][IDS[0]]['checks']
        self.assertTrue(checks[CRITERIA[31][0]])
        self.assertFalse(checks[CRITERIA[31][2]])
    def test_pre_d_policy_without_native_measure_never_full(self):
        t=self.fixture()
        scene=json.loads(t.contents['P1_SCENE_CONTRACT'][1])
        scene.update({'max_repeated_signature_ratio':1,
                      'min_material_variation_std':0.01,
                      'max_material_variation_std':255,
                      'max_variation_style_rgb_delta':255,
                      'max_silhouette_edge_mismatch':1})
        t.put('P1_SCENE_CONTRACT','p1_scene.json',encode(scene))
        t.rebuild()
        r=evaluate(self.context(t))
        self.assertTrue(r['rows'][IDS[6]]['checks'][CRITERIA[37][0]])
        self.assertTrue(r['rows'][IDS[6]]['checks'][CRITERIA[37][1]])
        self.assertFalse(r['rows'][IDS[7]]['checks'][CRITERIA[38][1]])
        self.assertTrue(all(row['full_rule_semantics']=='UNKNOWN'
                            for row in r['rows'].values()))
if __name__=='__main__':unittest.main()
