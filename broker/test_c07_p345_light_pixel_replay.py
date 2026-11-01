"""P345 macro adversarial tests: real original pixel arrays and GLB camera bounds.

Synthetic fixture inputs exercise the predicates only; they are not owner,
renderer, FiveM or MG0 evidence and do not promote a source-scoped rule.
"""
import unittest

from test_c07_p4_texture_semantics import png, solid
from test_c07_p345_forty_native_evidence import encoded
from test_c07_p4_lighting_player_full_review import P4LightingPlayerFullReviewTests
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_p4_material_macro_full_review import P4MaterialMacroTests
from c07_p345_light_pixel_replay import (
    neutral_pixel_qa, pixel_light_response, player_camera_horizontal_alignment)
from c07_p4_lighting_player_full_review import inspect as light_inspect
from c07_p345_remaining_original_review import inspect as remaining_inspect
from c07_p4_material_macro_full_review import inspect as material_inspect


def half_changed(original, changed):
    return png([[((changed if (x+y)%2 else original),)*3+(255,)
                 for x in range(4)] for y in range(4)])


class OriginalP345PixelAdversarial(unittest.TestCase):
    def test_pixel_predicates_reject_average_and_hash_only_forgery(self):
        neutral = png(solid(100))
        bright = png(solid(180))
        shadow = png(solid(30))
        self.assertTrue(neutral_pixel_qa(neutral))
        self.assertTrue(pixel_light_response(neutral,bright,direction=1,
                                              minimum_delta=20))
        self.assertTrue(pixel_light_response(neutral,shadow,direction=-1,
                                              minimum_delta=20))
        for changed in (half_changed(100,180),half_changed(100,30)):
            self.assertFalse(pixel_light_response(neutral,changed,
                             direction=1 if changed==half_changed(100,180) else -1,
                             minimum_delta=20))
        self.assertFalse(pixel_light_response(neutral,png(solid(180)),
                         direction=-1,minimum_delta=20))
        self.assertFalse(pixel_light_response(neutral,b'not a PNG',
                         direction=1))
        self.assertFalse(pixel_light_response(neutral,png(solid(100)),
                         direction=0))

    def test_neutral_mean_can_hide_severe_local_color_cast(self):
        rows = [[((255,0,0,255),(0,255,0,255),(0,0,255,255))[x%3]
                 for x in range(6)] for _ in range(6)]
        chromatic = png(rows)
        self.assertFalse(neutral_pixel_qa(chromatic))
        self.assertTrue(neutral_pixel_qa(png(solid(100))))

    def test_neutral_n131_rejects_equal_average_chromatic_pixels(self):
        obj=P4LightingPlayerFullReviewTests(
            'test_three_source_specific_positive_capture_replays_unknown_mg0')
        test,ctx=obj.context()
        chromatic=png([[((255,0,0,255),(0,255,0,255),(0,0,255,255))[x%3]
                        for x in range(6)] for _ in range(6)])
        test.add('LIGHT_NEUTRAL_VIEW','light_neutral_view.png',chromatic)
        obj.refresh(test,ctx)
        report=light_inspect(ctx,'AAA-200-N-131')
        self.assertFalse(report['checks'][
            'actual_neutral_view_pixels_redecoded_and_channel_balance_measured'])
        self.assertEqual(report['individual_mg0'],'UNKNOWN')

    def test_n132_rejects_50_percent_changed_pixels_despite_mean_delta(self):
        obj=P4LightingPlayerFullReviewTests(
            'test_three_source_specific_positive_capture_replays_unknown_mg0')
        test,ctx=obj.context()
        test.add('LIGHT_CINEMATIC_VIEW','light_cinematic_view.png',
                 half_changed(100,170))
        obj.refresh(test,ctx)
        report=light_inspect(ctx,'AAA-200-N-132')
        self.assertTrue(report['checks'][
            'actual_neutral_and_cinematic_pixel_arrays_independently_distinct'])
        self.assertFalse(report['checks'][
            'two_original_capture_modes_have_separate_source_roles_and_luminance'])

    def test_n137_rejects_camera_missed_native_horizontal_bounds(self):
        obj=P4LightingPlayerFullReviewTests(
            'test_three_source_specific_positive_capture_replays_unknown_mg0')
        test,ctx=obj.context()
        test.add('P4_PLAYER_CAMERA','p4_player_camera.json',encoded({
            'camera_xyz':[50,-3,1.7],'forward_xyz':[0,1,0]}))
        obj.refresh(test,ctx)
        report=light_inspect(ctx,'AAA-200-N-137')
        self.assertFalse(report['checks'][
            'measured_original_camera_at_player_height_and_facing_actual_asset'])
        self.assertFalse(player_camera_horizontal_alignment(
            [50,-3,1.7],[0,1,0],{'bbox_min':[0,0,0],'bbox_max':[1,1,0]}))

    def test_n134_n135_n136_n140_all_reject_mean_only_light_evidence(self):
        roles = {
            134:('LIGHT_DIRECT_VIEW',90,180),
            135:('LIGHT_SHADOW_VIEW',90,30),
            136:('REFLECTION_VIEW',90,170),
            140:('LIGHT_CINEMATIC_VIEW',90,130),
        }
        for number,(role,neutral,changed) in roles.items():
            with self.subTest(rule=number):
                obj=RemainingP345Tests('test_all_thirteen_have_distinct_real_source_predicates_no_full')
                test,ctx=obj.context()
                test.add(role,role.lower()+'.png',half_changed(neutral,changed))
                test.sync()
                ctx['controller']=test.f.controller
                report=remaining_inspect(ctx,'AAA-200-'+('N' if number<141 else 'O')+'-%03d'%number)
                self.assertFalse(report['checks'][
                    __import__('c07_p345_remaining_original_review').CRITERIA[number][1]])
                self.assertEqual(report['full_rule_semantics'],'UNKNOWN')

    def test_m122_material_light_source_requires_consistent_original_pixels(self):
        obj=P4MaterialMacroTests('test_all_seven_literal_rules_are_distinct_and_source_bound')
        test,ctx=obj.context()
        test.add('P4_VIEW_DIRECT','p4_view_direct.png',half_changed(90,180))
        test.sync()
        ctx['controller']=test.f.controller
        report=material_inspect(ctx,'AAA-200-M-122')
        self.assertFalse(report['checks'][
            'real_original_direct_neutral_shadow_pixels_follow_source_bounds'])
        self.assertEqual(report['individual_mg0'],'UNKNOWN')


if __name__=='__main__':
    unittest.main()
