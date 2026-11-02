"""C07 Q167-Q170 one macro of original source/tool boundary checks.

The tests intentionally prove source preflight, not live Sollumz, CodeWalker,
supported RAGE shaders, or FiveM. Four CANDIDATE rules cannot become FULL
from fake GUI logs, PNGs, or producer-approved metadata.
"""
import unittest
from c07_p7_q_four_crossformat_macro import RULES,METRICS,inspect
from c07_native_source_rule_replayers import FULL_LITERAL_REVIEWED,build_packet
from test_c07_p7_ten_structural_full_review import P7TenFullStructuralTests

class FourSourceMacro(unittest.TestCase):
    def setUp(self):
        self.fixture=P7TenFullStructuralTests(
          'test_four_external_execution_and_shader_claims_never_full')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def ctx(self):return self.fixture.ctx()

    def report(self,number):
        return inspect(self.ctx(),'AAA-200-Q-%03d'%number)

    def test_four_rules_independently_recomputed_never_falsify_execution(self):
        self.assertEqual(len(RULES),4)
        for n in (167,168,169,170):
            rid='AAA-200-Q-%03d'%n
            with self.subTest(rule=n):
                r=self.report(n)
                self.assertEqual(set(r['checks']),set(METRICS[n]))
                self.assertEqual(r['checks'][METRICS[n][-1]],False)
                self.assertEqual(r['full_rule_semantics'],'UNKNOWN')
                self.assertFalse(r['advancement_authorized'])
                self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
                packet=build_packet(self.ctx(),rid)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')

    def test_original_codewalker_position_and_three_pixels_recomputed(self):
        row=self.report(169)
        self.assertTrue(row['checks'][METRICS[169][0]])
        self.assertTrue(row['checks'][METRICS[169][1]])
        self.assertFalse(row['checks'][METRICS[169][2]])

    def test_codewalker_names_do_not_override_malformed_ymap_coordinates(self):
        self.fixture.q.files['P7_YMAP_XML']=b'<CMapData><entities/>'             b'</CMapData>'
        self.fixture.q.put()
        row=self.report(169)
        self.assertFalse(row['checks'][METRICS[169][0]])
        self.assertFalse(row['checks'][METRICS[169][1]])

    def test_fivem_label_and_numeric_frames_not_engine_proof(self):
        self.fixture.q.files['P7_RUNTIME_BUDGET']={
            'target_frame_ms':20}
        self.fixture.q.put()
        row=self.report(170)
        self.assertTrue(row['evidence_complete'])
        self.assertTrue(row['checks'][METRICS[170][0]])
        self.assertTrue(row['checks'][METRICS[170][1]])
        self.assertFalse(row['checks'][METRICS[170][2]])
        self.assertEqual(row['fivem_runtime'],'UNVERIFIED')

    def test_fivem_claimed_performance_over_pre_d_budget_rejected(self):
        self.fixture.q.files['P7_RUNTIME_BUDGET']={
            'target_frame_ms':8}
        self.fixture.q.put()
        row=self.report(170)
        self.assertTrue(row['checks'][METRICS[170][0]])
        self.assertFalse(row['checks'][METRICS[170][1]])

    def test_unsupported_rage_materials_not_accepted_by_shader_name(self):
        row=self.report(168)
        self.assertFalse(row['checks'][METRICS[168][1]])
        self.assertFalse(row['checks'][METRICS[168][2]])
        self.fixture.q.files['P7_SHADER_POLICY']={
           'allowed_shader_names':['unsupported'],
           'material_shader_map':{'fake':'unsupported'}}
        self.fixture.q.put()
        self.assertFalse(self.report(168)['checks'][METRICS[168][1]])

    def test_sollumz_tracename_not_same_as_real_blender_execution(self):
        row=self.report(167)
        self.assertFalse(row['checks'][METRICS[167][2]])
        self.fixture.q.files['P7_EXPORT_TRACE']['addon_version']='999.0.0'
        self.fixture.q.put()
        self.assertFalse(self.report(167)['checks'][METRICS[167][2]])

    def test_missing_pinned_original_budget_never_positive(self):
        self.fixture.q.files['P7_RUNTIME_BUDGET']={
            'target_frame_ms':18}
        self.fixture.q.put()
        self.fixture.q.f.plan['p678_evidence_contract'][
          'original_artifact_sha256'].pop('P7_RUNTIME_BUDGET')
        self.fixture.q.f.rebuild()
        row=self.report(170)
        self.assertFalse(row['evidence_complete'])
        self.assertFalse(row['checks'][METRICS[170][0]])

if __name__=='__main__':
    unittest.main()
