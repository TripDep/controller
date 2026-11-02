"""P155/P160/S190 macro: actual source bytes, not in-game/owner PASS."""
import json
import unittest
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p6_walkability_semantics import Tests as Walk, NORMALS
from test_c07_p8_final_qa_semantics import Tests as Final
from test_c07_p3_geometry_semantics import glb
from test_c07_positive_native_process import sha
from c07_native_source_rule_replayers import build_packet,FULL_LITERAL_REVIEWED
from c07_p678_three_residual_crosscheck_macro import (
  inspect,RULES,PREDICATES,P155,P160,S190)

class Supported(Walk):
    def setUp(self):
        super().setUp()
        self.policy['max_solid_collision_surface_gap_m']=.025
        self.put()

class Unsupported(Supported):
    def setUp(self):
        super().setUp()
        self.collision=glb([(0.1,0.1,0),(0.9,0.1,0),(0,0.8,0)],
                           [(0,1,2)],NORMALS)
        self.put()

class Telemetry(Walk):
    def setUp(self):
        super().setUp()
        self.policy['max_fivem_frame_p95_ms']=20
        self.put()
        log=b'UNVERIFIED labelled FiveM'
        self.f.add_item('FIVEM_COLLISION_RUNTIME_LOG','runtime.log',log)
        self.f.add_item('P6_WALKABILITY_RUNTIME_SAMPLES','samples.json',
                        json.dumps({'log_sha256':sha(log),
                          'frame_ms_samples':[12.5]*20}).encode())
        self.f.plan['p678_evidence_contract']['original_artifact_sha256'].update(
          {role:self.f.items[role]['sha256'] for role in
           ('FIVEM_COLLISION_RUNTIME_LOG','P6_WALKABILITY_RUNTIME_SAMPLES')})
        self.f.rebuild()

class OverBudget(Telemetry):
    def setUp(self):
        super().setUp()
        self.policy['max_fivem_frame_p95_ms']=10
        self.put()

class FakeOwner(Final):
    def setUp(self):
        super().setUp()
        self.docs['P8_INTERNAL_QA']['owner_approved']=True
        self.put()

class ThreeMacroTests(unittest.TestCase):
    def context(self,klass):
        method=('test_ten_distinct_original_scoped_observations_not_full_review'
                if issubclass(klass,Final) else
                'test_five_source_geometry_observations_runtime_unattested')
        self._last_fixture,ctx=NativeOriginalReplayerTests.context(self,klass,method)
        return ctx

    def read(self,klass,rid):
        context=self.context(klass)
        row=inspect(context,rid)
        self.assertEqual(set(row['checks']),set(PREDICATES[rid]))
        self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
        self.assertFalse(row['checks'][PREDICATES[rid][2]])
        self.assertFalse(row['advancement_authorized'])
        self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
        packet=build_packet(context,rid)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertIn(packet['mg0']['result'],('UNKNOWN','FAIL'))
        return row

    def test_three_rules_positive_source_only_and_no_owner_pass(self):
        self.assertEqual(RULES,{P155,P160,S190})
        for klass,rid in ((Supported,P155),(Telemetry,P160),(Final,S190)):
            with self.subTest(rule=rid):
                row=self.read(klass,rid)
                self.assertTrue(row['evidence_complete'])
                self.assertTrue(all(list(row['checks'].values())[:2]),row)

    def test_too_small_collision_triangle_never_guarantees_solid(self):
        row=self.read(Unsupported,P155)
        self.assertTrue(row['checks'][PREDICATES[P155][0]])
        self.assertFalse(row['checks'][PREDICATES[P155][1]])

    def test_producer_perf_telemetry_outside_pre_d_budget_rejected(self):
        row=self.read(OverBudget,P160)
        self.assertTrue(row['checks'][PREDICATES[P160][0]])
        self.assertFalse(row['checks'][PREDICATES[P160][1]])

    def test_owner_claim_in_internal_qa_cannot_certify_customer_defects(self):
        row=self.read(FakeOwner,S190)
        self.assertTrue(row['checks'][PREDICATES[S190][0]])
        self.assertFalse(row['checks'][PREDICATES[S190][1]])

    def test_missing_original_log_sha_pin_prevents_runtime_claim(self):
        context=self.context(Telemetry)
        context['plan']['p678_evidence_contract'][
           'original_artifact_sha256'].pop('FIVEM_COLLISION_RUNTIME_LOG')
        self._last_fixture.f.rebuild()
        row=inspect(context,P160)
        self.assertFalse(row['evidence_complete'])
        self.assertFalse(row['checks'][PREDICATES[P160][0]])
        self.assertFalse(row['checks'][PREDICATES[P160][2]])

    def test_forged_current_attempt_fails_before_semantic_replay(self):
        context=self.context(Supported)
        context['work']=dict(context['work'],attempt_id='0'*64)
        with self.assertRaises(ValueError):
            inspect(context,P155)

def load_tests(loader,tests,pattern):
    # The modified temporary source fixtures deliberately override setup,
    # so their inherited baseline tests must NOT be collected separately.
    # The six adversarial macro tests exercise those variants explicitly.
    return loader.loadTestsFromTestCase(ThreeMacroTests)

if __name__=='__main__':
    unittest.main()
