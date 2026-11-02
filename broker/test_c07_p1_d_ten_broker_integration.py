"""C07 D31-D40 ten-rule macro integration into native consuming broker.

Every packet MUST digest the additional ten-original-source, thirty-criterion
review, independently of the existing eight per-rule source predicates.
Neither checked source geometry nor synthetic rasters prove artistic/MG0 PASS.
"""
import copy
import unittest
from test_c07_p1_residual_macro_replay import P1ResidualSourceReplayTests
from c07_native_source_rule_replayers import build_packet,FULL_LITERAL_REVIEWED
from c07_p1_d_ten_original_semantic_review import IDS,CRITERIA,evaluate
from test_c07_p1_thirty_native_domain import encode

class TenDesignMacroBrokerTests(unittest.TestCase):
    def fixture(self):
        t=P1ResidualSourceReplayTests('test_whole_ten_literal_original_eight_check_macro')
        t.setUp()
        self.addCleanup(t.doCleanups)
        return t

    def test_all_ten_native_packets_include_same_full_macro_and_own_measurements(self):
        t=self.fixture()
        source=t.fixture()
        ctx=t.context(source)
        reference=evaluate(ctx)
        self.assertEqual(len(IDS),10)
        self.assertEqual(sum(len(x['checks']) for x in reference['rows'].values()),30)
        for rid in IDS:
            with self.subTest(rule=rid):
                packet=build_packet(ctx,rid)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertIn('proof_digest',packet['rule'])
                # A full independently reopened source family report must be
                # consulted, not a legacy eight-criterion filename checklist.
                self.assertEqual(reference['rows'][rid]['full_rule_semantics'],
                                 'UNKNOWN')
                self.assertFalse(reference['rows'][rid]['advancement_authorized'])

    def test_ten_packet_digests_react_to_current_source_mutation(self):
        t=self.fixture()
        source=t.fixture()
        ctx=t.context(source)
        before={rid:build_packet(ctx,rid)['rule']['proof_digest'] for rid in IDS}
        # Re-authorize modified original artifact bytes ONLY in this temporary
        # synthetic fixture; user's original assets remain untouched.
        source.scene['style_max_mean_rgb_delta']=0
        source.install()
        ctx=t.context(source)
        after={rid:build_packet(ctx,rid)['rule']['proof_digest'] for rid in IDS}
        self.assertTrue(all(before[rid]!=after[rid] for rid in IDS))

    def test_missing_source_pin_never_returns_d_full(self):
        t=self.fixture()
        source=t.fixture()
        ctx=t.context(source)
        ctx['plan']['p1_evidence_contract'][
            'original_artifact_sha256'].pop('P1_SCENE_CONTRACT')
        source.fixture.f.rebuild()
        for rid in IDS:
            with self.subTest(rule=rid):
                packet=build_packet(t.context(source),rid)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertNotIn(rid,FULL_LITERAL_REVIEWED)

    def test_original_master_and_attempt_remain_immutable(self):
        t=self.fixture()
        source=t.fixture()
        ctx=t.context(source)
        first=build_packet(ctx,IDS[0])
        altered=copy.deepcopy(ctx)
        altered['work']['attempt_id']='0'*64
        with self.assertRaises(ValueError):
            build_packet(altered,IDS[0])
        self.assertEqual(first['rule']['result'],'UNKNOWN')

if __name__=='__main__':
    unittest.main()
