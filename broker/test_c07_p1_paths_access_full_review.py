"""Independent P1 E-044/E-045 source geometry and adversarial replay tests."""
import copy
import json
import unittest

import supervisor_judgment as judgment
from c07_native_source_rule_replayers import (
    NATIVE_RULES, VALIDATORS, build_packet, native_rule_readback)
from c07_native_replayer_dispatch import replay
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty, encode

PATH = 'AAA-200-E-044'
ZONE = 'AAA-200-E-045'


class PathAccessFullReviewTests(unittest.TestCase):
    def context(self):
        test, ctx = NativeOriginalReplayerTests.context(
            self, P1Thirty, 'test_exact_30_individual_P1_and_90_unique_predicates')
        doc = json.loads(test.contents['P1_PATHS_GEOJSON'][1])
        doc['features'] = [
            {'properties': {'id': 'main-east', 'class': 'main'},
             'geometry': {'type': 'LineString',
                          'coordinates': [[0,0],[1,0]]}},
            {'properties': {'id': 'secondary-north', 'class': 'secondary'},
             'geometry': {'type': 'LineString',
                          'coordinates': [[0.5,0],[0.5,1]]}},
        ]
        doc['zones'] = [
            {'zone_id':'walkable', 'access':'ACCESSIBLE',
             'allowed_actors':['pedestrian'],
             'polygon':[[0,0],[0.5,0],[0.5,1],[0,1],[0,0]]},
            {'zone_id':'restricted', 'access':'EXCLUDED',
             'allowed_actors':[],
             'polygon':[[0.5,0],[1,0],[1,1],[0.5,1],[0.5,0]]},
        ]
        test.put('P1_PATHS_GEOJSON','paths.json',encode(doc))
        test.rebuild()
        ctx['controller'] = test.f.controller
        return test,ctx,doc

    def rewrite(self,test,ctx,doc):
        test.put('P1_PATHS_GEOJSON','paths.json',encode(doc))
        test.rebuild()
        ctx['controller'] = test.f.controller

    def spec(self,ctx,rid):
        expected = judgment.binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        return expected, {'validator_id':VALIDATORS[rid],
            'criteria':list(NATIVE_RULES[rid][1]),
            'requirement_sha256':expected['requirement_sha256'],
            'source_ref':'1'*40}

    def test_both_source_specific_positive_and_independent_consumer_replay(self):
        _,ctx,_ = self.context()
        for rid in (PATH,ZONE):
            with self.subTest(rid=rid):
                packet = build_packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'PASS')
                self.assertTrue(all(packet['rule']['checks'].values()))
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                expected,spec = self.spec(ctx,rid)
                result = replay(None,packet,expected,spec,
                                source_context=lambda _:ctx)
                self.assertEqual(result['documentary_result'],'PASS')
                self.assertFalse(result['advancement_authorized'])
                forged = copy.deepcopy(packet)
                forged['rule']['checks'][NATIVE_RULES[rid][1][1]]=False
                with self.assertRaisesRegex(ValueError,
                                            'PRODUCER_PACKET_NOT_RECOMPUTED'):
                    native_rule_readback(None,forged,expected,spec,
                                         source_context=lambda _:ctx)

    def test_path_isolation_and_fake_classification_fail(self):
        test,ctx,doc=self.context()
        doc['features'][1]['geometry']['coordinates']=[[0.6,0.6],[0.9,0.9]]
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,PATH)['rule']['result'],'FAIL')
        doc['features'][1]['properties']['class']='main'
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,PATH)['rule']['result'],'FAIL')

    def test_path_duplicate_ids_and_zero_length_fail(self):
        test,ctx,doc=self.context()
        doc['features'][1]['properties']['id']='main-east'
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,PATH)['rule']['result'],'FAIL')
        doc['features'][1]['properties']['id']='secondary-north'
        doc['features'][1]['geometry']['coordinates']=[[0.5,0],[0.5,0]]
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,PATH)['rule']['result'],'FAIL')

    def test_access_exclusion_overlap_and_actor_mislabel_fail(self):
        test,ctx,doc=self.context()
        doc['zones'][1]['polygon']=[
            [0.4,0],[1,0],[1,1],[0.4,1],[0.4,0]]
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,ZONE)['rule']['result'],'FAIL')
        doc['zones'][1]['polygon']=[
            [0.5,0],[1,0],[1,1],[0.5,1],[0.5,0]]
        doc['zones'][1]['allowed_actors']=['pedestrian']
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,ZONE)['rule']['result'],'FAIL')

    def test_self_intersecting_zone_and_duplicate_zone_id_fail(self):
        test,ctx,doc=self.context()
        doc['zones'][0]['polygon']=[
            [0,0],[0.5,1],[0,1],[0.5,0],[0,0]]
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,ZONE)['rule']['result'],'FAIL')
        doc['zones'][0]['polygon']=[
            [0,0],[0.5,0],[0.5,1],[0,1],[0,0]]
        doc['zones'][1]['zone_id']='walkable'
        self.rewrite(test,ctx,doc)
        self.assertEqual(build_packet(ctx,ZONE)['rule']['result'],'FAIL')

    def test_missing_pre_d_geojson_pin_is_unknown(self):
        test,ctx,_=self.context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_PATHS_GEOJSON')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        for rid in (PATH,ZONE):
            self.assertEqual(build_packet(ctx,rid)['rule']['result'],'UNKNOWN')

    def test_changed_original_and_wrong_attempt_rejected(self):
        test,ctx,_=self.context()
        (test.f.root/'paths.json').write_bytes(b'{"features":[]}')
        with self.assertRaises(ValueError):
            build_packet(ctx,PATH)
        _,ctx,_=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,ZONE)


if __name__=='__main__':
    unittest.main()
