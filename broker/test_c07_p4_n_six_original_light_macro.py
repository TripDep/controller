"""C07 six-rule N-P4 original-source lighting macro regression suite.

No simulated RENDER_CAPTURED or QA event implies real renderer provenance.
The legacy scoped readings remain untouched; all six new independent
checks are attached to the consuming-side proof and fail closed.
"""
import unittest
from test_c07_p345_remaining_original_review import (
    RemainingP345Tests,reversed_winding_native)
from c07_p4_n_six_original_light_macro import (
    inspect,RULES,CODES,CAPTURES)
from c07_native_source_rule_replayers import build_packet,FULL_LITERAL_REVIEWED
from test_c07_positive_native_process import canonical,sha
from test_c07_p345_forty_native_evidence import encoded

class P4SixOriginalSourceTests(unittest.TestCase):
    def setUp(self):
        self.t=RemainingP345Tests(
            'test_positive_source_benefits_measured_not_promoted_to_full')
        self.t.setUp()
        self.addCleanup(self.t.doCleanups)
        self.test,self.ctx=self.t.context()

    def append(self,event,**data):
        f=self.test.f
        row={'asset':f.asset,'event':event,
             'prev_hash':f.records[-1]['record_hash'],
             'step':f.step,'attempt_id':f.work['attempt_id'],
             'operation_sha256':f.work['operation_sha256'],**data}
        row['record_hash']=sha(canonical(row))
        f.records.append(row)
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(x)+bytes([10]) for x in f.records))
        f.controller._state['last_audit_hash']=row['record_hash']
        self.ctx['controller']=f.controller

    def captures(self,number):
        for role in CAPTURES[number]:
            self.append('RENDER_CAPTURED',source_role=role,
                image_sha256=sha(self.test.art[role]))

    def assert_unknown(self,number):
        rid='AAA-200-N-%03d'%number
        self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
        result=inspect(self.ctx,rid)
        self.assertEqual(set(result['checks']),set(CODES[number]))
        self.assertEqual(result['individual_mg0'],'UNKNOWN')
        self.assertFalse(result['advancement_authorized'])
        packet=build_packet(self.ctx,rid)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        return result

    def test_six_literal_source_macros_are_integrated_without_renderer_pass(self):
        self.assertEqual(len(RULES),6)
        for number in (133,134,135,136,139,140):
            with self.subTest(rule=number):
                r=self.assert_unknown(number)
                self.assertFalse(r['checks'][CODES[number][0]])
                self.assertEqual(r['current_original_capture_roles'],())
                self.assertEqual(r['renderer_execution_provenance'],'UNVERIFIED')

    def test_original_three_light_capture_events_recompute_real_pixel_ramps(self):
        self.captures(134)
        for number in (134,135):
            with self.subTest(rule=number):
                r=self.assert_unknown(number)
                self.assertTrue(all(r['checks'].values()),r['checks'])
                self.assertEqual(len(r['current_original_capture_roles']),3)

    def test_original_metallic_reflection_pixels_are_distinct_from_neutral(self):
        self.captures(136)
        result=self.assert_unknown(136)
        self.assertTrue(all(result['checks'].values()),result['checks'])

    def test_original_native_geometry_defect_report_recomputed_with_native_sha(self):
        f=self.test.f
        self.test.add('P4_GEOMETRY_DEFECT_REPORT','defects.json',
            encoded({'degenerate_triangle_count':0,
                     'native_sha256':sha(self.test.art['NATIVE_EXPORT'])}))
        self.test.sync()
        self.ctx['controller']=f.controller
        self.captures(133)
        result=self.assert_unknown(133)
        self.assertTrue(all(result['checks'].values()),result['checks'])
        self.test.add('P4_GEOMETRY_DEFECT_REPORT','defects.json',
            encoded({'degenerate_triangle_count':0,
                     'native_sha256':'0'*64}))
        self.test.sync()
        self.ctx['controller']=f.controller
        self.captures(133)
        result=self.assert_unknown(133)
        self.assertFalse(result['checks'][CODES[133][2]])

    def test_underside_requires_real_bottom_faces_not_image_label(self):
        self.captures(139)
        result=self.assert_unknown(139)
        self.assertFalse(result['checks'][CODES[139][2]])
        self.assertFalse(result['checks'][CODES[139][1]])

    def test_visual_and_technical_review_events_need_different_reviewer_ids(self):
        self.captures(140)
        self.append('VISUAL_QA_REVIEWED',review_kind='TECHNICAL',
            reviewer_id='reviewer-A',
            image_sha256=sha(self.test.art['LIGHT_NEUTRAL_VIEW']))
        self.append('VISUAL_QA_REVIEWED',review_kind='PRESENTATION',
            reviewer_id='reviewer-A',
            image_sha256=sha(self.test.art['LIGHT_CINEMATIC_VIEW']))
        result=self.assert_unknown(140)
        self.assertTrue(result['checks'][CODES[140][1]])
        self.assertFalse(result['checks'][CODES[140][2]])

    def test_original_capture_hash_forgery_is_detected(self):
        self.append('RENDER_CAPTURED',source_role='LIGHT_DIRECT_VIEW',
            image_sha256='0'*64)
        r=self.assert_unknown(134)
        self.assertFalse(r['checks'][CODES[134][0]])

    def test_missing_original_png_pin_never_counts_as_capture(self):
        self.captures(136)
        f=self.test.f
        f.plan['p345_evidence_contract']['original_artifact_sha256'].pop(
            'REFLECTION_VIEW')
        f.rebuild()
        self.ctx['controller']=f.controller
        r=self.assert_unknown(136)
        self.assertFalse(r['evidence_complete'])
        self.assertFalse(r['checks'][CODES[136][0]])

if __name__=='__main__':
    unittest.main()
