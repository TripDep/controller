"""P3-P5 pending 14-rule macro: invisible original captures are not evidence.

Twelve P4/P5 source predicates consume QA PNGs. CRC-valid RGBA files with
alpha=0 can carry arbitrarily convincing RGB without rendering any visible
asset. Every relevant original-byte reader must reject that adversarial source.
The remaining M129 shader and O150 runtime obligations stay UNKNOWN without
independent RAGE/FiveM provenance. No fixture is an MG0 or owner approval.
"""
import unittest

from test_c07_p4_texture_semantics import png, solid
from test_c07_p345_forty_native_evidence import encoded
from test_c07_p4_lighting_player_full_review import P4LightingPlayerFullReviewTests
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_p4_material_macro_full_review import P4MaterialMacroTests
from c07_p345_light_pixel_replay import (
    opaque_capture_png, original_pixels, pixel_light_response,
    lod_view_color_distance)
from c07_p4_lighting_player_full_review import inspect as lighting
from c07_p345_remaining_original_review import inspect as remaining
from c07_p4_material_macro_full_review import inspect as material
from c07_native_source_rule_replayers import FULL_LITERAL_REVIEWED

PENDING = (
    'AAA-200-M-122', 'AAA-200-M-129', 'AAA-200-M-130',
    'AAA-200-N-131', 'AAA-200-N-132', 'AAA-200-N-133',
    'AAA-200-N-134', 'AAA-200-N-135', 'AAA-200-N-136',
    'AAA-200-N-137', 'AAA-200-N-139', 'AAA-200-N-140',
    'AAA-200-O-145', 'AAA-200-O-150',
)
CAPTURE_CASES = (
    (122, 'P4_VIEW_DIRECT', 180, 'material'),
    (130, 'P4_VIEW_DIRECT', 180, 'material'),
    (131, 'LIGHT_NEUTRAL_VIEW', 100, 'lighting'),
    (132, 'LIGHT_CINEMATIC_VIEW', 170, 'lighting'),
    (133, 'LIGHT_NEUTRAL_VIEW', 90, 'remaining'),
    (134, 'LIGHT_DIRECT_VIEW', 180, 'remaining'),
    (135, 'LIGHT_SHADOW_VIEW', 30, 'remaining'),
    (136, 'REFLECTION_VIEW', 170, 'remaining'),
    (137, 'VISUAL_PLAYER_VIEW', 90, 'lighting'),
    (139, 'VISUAL_VIEW_UNDERSIDE', 110, 'remaining'),
    (140, 'LIGHT_CINEMATIC_VIEW', 130, 'remaining'),
    (145, 'LOD_NEAR_VIEW', 80, 'remaining'),
)

def rgba(value, alpha):
    return png([[(value,value,value,alpha) for _ in range(4)]
                for _ in range(4)])

class P345PendingCaptureMacroTests(unittest.TestCase):
    def test_exact_fourteen_missing_literals_never_autopromoted(self):
        self.assertEqual(len(PENDING),14)
        self.assertEqual(len(CAPTURE_CASES),12)
        self.assertEqual({n for n,_,_,_ in CAPTURE_CASES},
                         {int(x[-3:]) for x in PENDING}-{129,150})
        self.assertFalse(set(PENDING)&set(FULL_LITERAL_REVIEWED))

    def test_original_rgb_not_visible_when_alpha_zero_or_partial(self):
        clear=rgba(120,255)
        for alpha in (0,1,127,254):
            with self.subTest(alpha=alpha):
                hidden=rgba(120,alpha)
                self.assertFalse(opaque_capture_png(hidden))
                self.assertIsNone(original_pixels(hidden))
                self.assertFalse(pixel_light_response(
                    clear,hidden,direction=0))
                self.assertFalse(lod_view_color_distance(clear,hidden,255))
        self.assertTrue(opaque_capture_png(clear))
        self.assertIsNotNone(original_pixels(clear))
        self.assertFalse(opaque_capture_png(b'fake original PNG'))

    def test_twelve_original_image_semantics_reject_alpha_hidden_capture(self):
        for number,role,value,family in CAPTURE_CASES:
            with self.subTest(rule=number,role=role):
                if family=='lighting':
                    helper=P4LightingPlayerFullReviewTests(
                        'test_three_source_specific_positive_capture_replays_unknown_mg0')
                    test,ctx=helper.context()
                    inspect=lighting
                elif family=='material':
                    helper=P4MaterialMacroTests(
                        'test_all_seven_literal_rules_are_distinct_and_source_bound')
                    test,ctx=helper.context()
                    inspect=material
                else:
                    helper=RemainingP345Tests(
                        'test_all_thirteen_have_distinct_real_source_predicates_no_full')
                    test,ctx=helper.context()
                    inspect=remaining
                    if number in (139,140):
                        test.add('P345_QA_REPORT','p345_qa_report.json',
                                 encoded({'unresolved_findings':[]}))
                    if number in (134,135,140):
                        test.add('P4_LIGHTING_QA','p4_lighting_qa.json',
                                 encoded({'presentation_mode':'STUDIO_ONLY'}))
                    if number==136:
                        test.add('P4_MATERIAL_PLAN','p4_material_plan.json',
                                 encoded({'fivem_shader_profile':'GTA5_NATIVE_RAGE'}))
                    test.sync()
                    ctx['controller']=test.f.controller
                rid='AAA-200-'+('M' if number<=130 else
                    'N' if number<=140 else 'O')+'-%03d'%number
                baseline=inspect(ctx,rid)
                self.assertTrue(any(baseline['checks'].values()),
                    'fixture lacks a positive original source observation: '+rid)
                test.add(role,role.lower()+'.png',rgba(value,0))
                if family=='lighting':
                    helper.refresh(test,ctx)
                else:
                    test.sync()
                    ctx['controller']=test.f.controller
                hidden=inspect(ctx,rid)
                self.assertTrue(any(
                    passed and not hidden['checks'][criterion]
                    for criterion,passed in baseline['checks'].items()),
                    'invisible original capture still accepted: '+rid)
                self.assertEqual(hidden['individual_mg0'],'UNKNOWN')
                self.assertFalse(hidden['advancement_authorized'])

    def test_shader_and_runtime_sources_not_independent_proof(self):
        material_helper=P4MaterialMacroTests(
            'test_all_seven_literal_rules_are_distinct_and_source_bound')
        _,ctx=material_helper.context()
        shader=material(ctx,'AAA-200-M-129')
        self.assertEqual(shader['individual_mg0'],'UNKNOWN')
        self.assertFalse(shader['advancement_authorized'])
        remaining_helper=RemainingP345Tests(
            'test_all_thirteen_have_distinct_real_source_predicates_no_full')
        _,ctx=remaining_helper.context()
        runtime=remaining(ctx,'AAA-200-O-150')
        self.assertEqual(runtime['full_rule_semantics'],'UNKNOWN')
        self.assertEqual(runtime['fivem_runtime'],'UNKNOWN')
        self.assertFalse(runtime['advancement_authorized'])

if __name__=='__main__':
    unittest.main()
